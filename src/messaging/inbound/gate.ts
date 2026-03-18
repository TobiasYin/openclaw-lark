/**
 * Copyright (c) 2026 ByteDance Ltd. and/or its affiliates
 * SPDX-License-Identifier: MIT
 *
 * Policy gate for inbound Feishu messages.
 *
 * Determines whether a parsed message should be processed or rejected
 * based on group/DM access policies, sender allowlists, and mention
 * requirements.
 *
 * Group access follows the same two-layer model as Telegram:
 *
 *   Layer 1 – Which GROUPS are allowed (SDK `resolveGroupPolicy`):
 *     - No `groups` configured + `groupPolicy: "open"` → any group passes
 *     - `groupPolicy: "allowlist"` or `groups` configured → acts as allowlist
 *       (explicit group IDs or `"*"` wildcard)
 *     - `groupPolicy: "disabled"` → all groups blocked
 *
 *   Layer 2 – Which SENDERS are allowed within a group:
 *     - Per-group `groupPolicy` overrides the global groupPolicy for sender filtering
 *     - `groupAllowFrom` (global) + per-group `allowFrom` are merged
 *     - `"open"` → any sender; `"allowlist"` → check merged list;
 *       `"disabled"` → block all senders
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ClawdbotConfig, HistoryEntry } from 'openclaw/plugin-sdk';
import type { MessageContext } from '../types';
import type { FeishuConfig } from '../../core/types';
import type { LarkAccount } from '../../core/types';
import { LarkClient } from '../../core/lark-client';
import {
  resolveFeishuGroupConfig,
  resolveFeishuAllowlistMatch,
  isFeishuGroupAllowed,
  splitLegacyGroupAllowFrom,
  resolveGroupSenderPolicyContext,
} from './policy';
import { mentionedBot } from './mention';
import { sendPairingReply } from './gate-effects';

/** Prevent spamming the legacy groupAllowFrom migration warning. */
let legacyGroupAllowFromWarned = false;

// ---------------------------------------------------------------------------
// Thread first-message persistence
// ---------------------------------------------------------------------------

/** Thread state with timestamp for TTL eviction */
const threadFirstMessageProcessed = new Map<string, number>(); // threadKey -> timestamp
let threadStateLoaded = false;

/** Persistence configuration defaults */
const DEFAULT_TTL_DAYS = 7;
const DEFAULT_MAX_ENTRIES = 10000;
const THREAD_STATE_FILE = path.join(process.env.HOME || '/tmp', '.openclaw', 'thread-first-message-state.json');

/** File lock for concurrent access */
let isSaving = false;
let pendingSave = false;

/** Load persisted state on startup with TTL eviction */
function loadThreadState(cfg?: FeishuConfig): void {
  try {
    if (fs.existsSync(THREAD_STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(THREAD_STATE_FILE, 'utf8')) as {
        threads?: Array<{ key: string; ts: number } | string>;
        updatedAt?: string;
      };
      const persistenceCfg = cfg?.threadFirstReplyPersistence;
      const ttlDays = persistenceCfg?.ttlDays ?? DEFAULT_TTL_DAYS;
      const ttlMs = ttlDays * 24 * 60 * 60 * 1000;
      const now = Date.now();

      if (data.threads && Array.isArray(data.threads)) {
        let loaded = 0;
        let evicted = 0;

        for (const entry of data.threads) {
          // Support both old format (string) and new format (object with timestamp)
          if (typeof entry === 'string') {
            threadFirstMessageProcessed.set(entry, now);
            loaded++;
          } else if (entry.key && entry.ts) {
            const age = now - entry.ts;
            if (age < ttlMs) {
              threadFirstMessageProcessed.set(entry.key, entry.ts);
              loaded++;
            } else {
              evicted++;
            }
          }
        }

        if (evicted > 0) {
          console.log(`[feishu] Loaded ${loaded} thread states, evicted ${evicted} expired entries (TTL: ${ttlDays} days)`);
          queueSaveThreadState();
        } else {
          console.log(`[feishu] Loaded ${loaded} thread states from ${THREAD_STATE_FILE}`);
        }
      }
    }
  } catch (err) {
    console.error(`[feishu] Failed to load thread state: ${(err as Error).message}`);
  }
}

/** Queue save with debouncing to handle concurrent writes */
function queueSaveThreadState(): void {
  if (isSaving) {
    pendingSave = true;
    return;
  }

  isSaving = true;
  pendingSave = false;

  try {
    doSaveThreadState();
  } finally {
    isSaving = false;
    if (pendingSave) {
      setTimeout(() => queueSaveThreadState(), 100);
    }
  }
}

/** Actual save implementation with eviction */
function doSaveThreadState(): void {
  try {
    const dir = path.dirname(THREAD_STATE_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Get all entries sorted by timestamp (oldest first)
    const entries = Array.from(threadFirstMessageProcessed.entries())
      .map(([key, ts]) => ({ key, ts }))
      .sort((a, b) => a.ts - b.ts);

    // Apply max entries limit (remove oldest)
    const maxEntries = DEFAULT_MAX_ENTRIES;
    if (entries.length > maxEntries) {
      const toRemove = entries.length - maxEntries;
      for (let i = 0; i < toRemove; i++) {
        threadFirstMessageProcessed.delete(entries[i].key);
      }
      console.log(`[feishu] Evicted ${toRemove} oldest thread entries (max: ${maxEntries})`);
    }

    const data = {
      threads: Array.from(threadFirstMessageProcessed.entries()).map(([key, ts]) => ({ key, ts })),
      updatedAt: new Date().toISOString(),
    };

    // Atomic write: write to temp file then rename
    const tempFile = `${THREAD_STATE_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
    fs.renameSync(tempFile, THREAD_STATE_FILE);
  } catch (err) {
    console.error(`[feishu] Failed to save thread state: ${(err as Error).message}`);
  }
}

/** Save state to file (public API) */
function saveThreadState(): void {
  queueSaveThreadState();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Read the pairing allowFrom store for the Feishu channel via the SDK runtime.
 */
async function readAllowFromStore(accountId: string): Promise<string[]> {
  const core = LarkClient.runtime;
  return await core.channel.pairing.readAllowFromStore({
    channel: 'feishu',
    accountId,
  });
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GateResult {
  allowed: boolean;
  reason?: string;
  /** When a group message is rejected due to missing bot mention, the
   *  caller should record this entry into the chat history map. */
  historyEntry?: HistoryEntry;
  /** When threadFirstReplyWithoutMention is enabled and this is a non-first
   *  message without mention, this is true. The caller should process the
   *  message (for context) but skip the actual reply. */
  skipReply?: boolean;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Read the pairing allowFrom store for the Feishu channel.
 *
 * Exported so that handler.ts can provide it as a closure to the SDK's
 * `resolveSenderCommandAuthorization` helper.
 */
export { readAllowFromStore as readFeishuAllowFromStore };

/**
 * Check whether an inbound message passes all access-control gates.
 *
 * The DM gate is async because it may read from the pairing store
 * and send pairing request messages.
 */
export async function checkMessageGate(params: {
  ctx: MessageContext;
  accountFeishuCfg?: FeishuConfig;
  account: LarkAccount;
  /** account 级别的 ClawdbotConfig（channels.feishu 已替换为 per-account 合并后的配置） */
  accountScopedCfg?: ClawdbotConfig;
  log: (...args: unknown[]) => void;
  /** Chat histories map (kept for API compatibility but not used for thread tracking) */
  chatHistories?: Map<string, HistoryEntry[]>;
}): Promise<GateResult> {
  const { ctx, accountFeishuCfg, account, accountScopedCfg, log } = params;
  const isGroup = ctx.chatType === 'group';

  // Lazy load thread state with config when first message arrives
  if (!threadStateLoaded && accountFeishuCfg) {
    threadStateLoaded = true;
    loadThreadState(accountFeishuCfg);
  }

  if (isGroup) {
    return checkGroupGate({ ctx, accountFeishuCfg, account, accountScopedCfg, log });
  }

  return checkDmGate({ ctx, accountFeishuCfg, account, accountScopedCfg, log });
}

// ---------------------------------------------------------------------------
// Internal: group gate
// ---------------------------------------------------------------------------

function checkGroupGate(params: {
  ctx: MessageContext;
  accountFeishuCfg?: FeishuConfig;
  account: LarkAccount;
  accountScopedCfg?: ClawdbotConfig;
  log: (...args: unknown[]) => void;
}): GateResult {
  const { ctx, accountFeishuCfg, account, accountScopedCfg, log } = params;
  const core = LarkClient.runtime;

  // ---- Legacy compat: groupAllowFrom with chat_id entries ----
  // Older Feishu configs used groupAllowFrom with chat_ids (oc_xxx) to
  // control which groups are allowed.  The correct semantic (aligned with
  // Telegram) is sender_ids.  Detect and split so both layers still work.
  const rawGroupAllowFrom = accountFeishuCfg?.groupAllowFrom ?? [];
  const { legacyChatIds, senderAllowFrom: senderGroupAllowFrom } = splitLegacyGroupAllowFrom(rawGroupAllowFrom);

  if (legacyChatIds.length > 0 && !legacyGroupAllowFromWarned) {
    legacyGroupAllowFromWarned = true;
    log(
      `feishu[${account.accountId}]: ⚠️  groupAllowFrom contains chat_id entries ` +
        `(${legacyChatIds.join(', ')}). groupAllowFrom is for SENDER filtering ` +
        `(open_ids like ou_xxx). Please move chat_ids to "groups" config instead:\n` +
        `  channels.feishu.groups: {\n` +
        legacyChatIds.map((id) => `    "${id}": {},`).join('\n') +
        `\n  }`,
    );
  }

  // ---- Layer 1: Group-level access (SDK) ----
  // The SDK reads `channels.feishu.groups` as an allowlist of group IDs.
  // - No groups configured + groupPolicy "open" → any group passes
  // - groupPolicy "allowlist" (or groups configured) → only listed groups pass
  // - groupPolicy "disabled" → all groups blocked
  const groupAccess = core.channel.groups.resolveGroupPolicy({
    cfg: accountScopedCfg ?? {},
    channel: 'feishu',
    groupId: ctx.chatId,
    accountId: account.accountId,
    groupIdCaseInsensitive: true,
    hasGroupAllowFrom: senderGroupAllowFrom.length > 0,
  });

  // Legacy compat: if SDK rejects the group but the chat_id is in the
  // old-style groupAllowFrom, allow it (backward compatibility).
  // Track whether this group was admitted via legacy path so we can skip
  // sender filtering below (old semantic: chat_id in groupAllowFrom meant
  // "allow this group for any sender").
  let legacyGroupAdmit = false;
  if (!groupAccess.allowed) {
    const chatIdLower = ctx.chatId.toLowerCase();
    const legacyMatch = legacyChatIds.some((id) => String(id).toLowerCase() === chatIdLower);
    if (!legacyMatch) {
      log(`feishu[${account.accountId}]: group ${ctx.chatId} blocked by group-level policy`);
      return { allowed: false, reason: 'group_not_allowed' };
    }
    legacyGroupAdmit = true;
  }

  // ---- Per-group config (Feishu-specific fields) ----
  const groupConfig = resolveFeishuGroupConfig({
    cfg: accountFeishuCfg,
    groupId: ctx.chatId,
  });
  const defaultConfig = accountFeishuCfg?.groups?.['*'];

  // Per-group enabled flag
  const enabled = groupConfig?.enabled ?? defaultConfig?.enabled;
  if (enabled === false) {
    log(`feishu[${account.accountId}]: group ${ctx.chatId} disabled by per-group config`);
    return { allowed: false, reason: 'group_disabled' };
  }

  // ---- Layer 2: Sender-level access ----
  // Per-group groupPolicy overrides the global groupPolicy for sender filtering.
  // senderGroupAllowFrom (global, oc_ entries excluded) + per-group allowFrom.
  //
  // Legacy compat: when a group was admitted via old-style chat_id in
  // groupAllowFrom AND there is no explicit per-group sender config,
  // skip sender filtering (old semantic = "group allowed, any sender").
  const hasExplicitSenderConfig =
    senderGroupAllowFrom.length > 0 || (groupConfig?.allowFrom ?? []).length > 0 || groupConfig?.groupPolicy != null;

  if (!(legacyGroupAdmit && !hasExplicitSenderConfig)) {
    const { senderPolicy, senderAllowFrom } = resolveGroupSenderPolicyContext({
      groupConfig,
      defaultConfig,
      accountFeishuCfg,
      senderGroupAllowFrom,
    });

    const senderAllowed = isFeishuGroupAllowed({
      groupPolicy: senderPolicy,
      allowFrom: senderAllowFrom,
      senderId: ctx.senderId,
      senderName: ctx.senderName,
    });

    if (!senderAllowed) {
      log(`feishu[${account.accountId}]: sender ${ctx.senderId} not allowed in group ${ctx.chatId}`);
      return { allowed: false, reason: 'sender_not_allowed' };
    }
  }

  // ---- Mention requirement (SDK) ----
  // SDK precedence: per-group > default ("*") > requireMentionOverride > true
  const requireMention = core.channel.groups.resolveRequireMention({
    cfg: accountScopedCfg ?? {},
    channel: 'feishu',
    groupId: ctx.chatId,
    accountId: account.accountId,
    groupIdCaseInsensitive: true,
    requireMentionOverride: accountFeishuCfg?.requireMention,
  });

  // Thread first-message auto-reply support
  // If requireMention is true and bot is not mentioned, check if this is
  // the first message in a thread and threadFirstReplyWithoutMention is enabled.
  if (requireMention && !mentionedBot(ctx)) {
    // Check if threadFirstReplyWithoutMention is enabled for this group
    const threadFirstReplyWithoutMention =
      groupConfig?.threadFirstReplyWithoutMention ??
      defaultConfig?.threadFirstReplyWithoutMention ??
      accountFeishuCfg?.threadFirstReplyWithoutMention ??
      false;

    // Check if this is a thread message
    if (threadFirstReplyWithoutMention && ctx.threadId) {
      const threadKey = `${ctx.chatId}:thread:${ctx.threadId}`;
      // If this thread hasn't been processed yet, allow the first message
      if (!threadFirstMessageProcessed.has(threadKey)) {
        // Mark this thread as processed with current timestamp
        threadFirstMessageProcessed.set(threadKey, Date.now());
        saveThreadState(); // Persist to file
        return { allowed: true };
      }
      // Thread has been processed before, this is a non-first message without mention
      // Allow it to pass for context, but mark to skip the reply
      return { allowed: true, skipReply: true };
    }

    log(`feishu[${account.accountId}]: message in group ${ctx.chatId} did not mention bot, recording to history`);

    return {
      allowed: false,
      reason: 'no_mention',
      historyEntry: {
        sender: ctx.senderId,
        body: `${ctx.senderName ?? ctx.senderId}: ${ctx.content}`,
        timestamp: Date.now(),
        messageId: ctx.messageId,
      },
    };
  }

  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Internal: DM gate
// ---------------------------------------------------------------------------

async function checkDmGate(params: {
  ctx: MessageContext;
  accountFeishuCfg?: FeishuConfig;
  account: LarkAccount;
  accountScopedCfg?: ClawdbotConfig;
  log: (...args: unknown[]) => void;
}): Promise<GateResult> {
  const { ctx, accountFeishuCfg, account, accountScopedCfg, log } = params;

  const dmPolicy = accountFeishuCfg?.dmPolicy ?? 'pairing';
  const configAllowFrom = accountFeishuCfg?.allowFrom ?? [];

  if (dmPolicy === 'disabled') {
    log(`feishu[${account.accountId}]: DM disabled by policy, rejecting sender ${ctx.senderId}`);
    return { allowed: false, reason: 'dm_disabled' };
  }

  if (dmPolicy === 'open') {
    return { allowed: true };
  }

  if (dmPolicy === 'allowlist') {
    const storeAllowFrom = await readAllowFromStore(account.accountId).catch(() => [] as string[]);
    const combinedAllowFrom = [...configAllowFrom, ...storeAllowFrom];

    const match = resolveFeishuAllowlistMatch({
      allowFrom: combinedAllowFrom,
      senderId: ctx.senderId,
      senderName: ctx.senderName,
    });
    if (!match.allowed) {
      log(`feishu[${account.accountId}]: sender ${ctx.senderId} not in DM allowlist`);
      return { allowed: false, reason: 'dm_not_allowed' };
    }
    return { allowed: true };
  }

  // dmPolicy === "pairing"
  const storeAllowFrom = await readAllowFromStore(account.accountId).catch(() => [] as string[]);
  const combinedAllowFrom = [...configAllowFrom, ...storeAllowFrom];

  const match = resolveFeishuAllowlistMatch({
    allowFrom: combinedAllowFrom,
    senderId: ctx.senderId,
    senderName: ctx.senderName,
  });

  if (match.allowed) {
    return { allowed: true };
  }

  // Sender not yet paired — create a pairing request and notify them
  log(`feishu[${account.accountId}]: sender ${ctx.senderId} not paired, creating pairing request`);
  try {
    await sendPairingReply({
      senderId: ctx.senderId,
      chatId: ctx.chatId,
      accountId: account.accountId,
      accountScopedCfg,
    });
  } catch (err) {
    log(`feishu[${account.accountId}]: failed to create pairing request for ${ctx.senderId}: ${String(err)}`);
  }

  return { allowed: false, reason: 'pairing_pending' };
}
