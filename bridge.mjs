/**
 * Feishu ↔ Clawdbot Bridge
 *
 * Receives messages from Feishu via WebSocket (long connection),
 * forwards them to Clawdbot Gateway, and sends the AI reply back.
 *
 * Design goals:
 * - Robust: never silently drop messages just because parsing failed.
 * - Long-term: tolerate Feishu rich-text (post/md/list) structure variations.
 * - Practical: handle images from (1) real Feishu image messages, (2) post embeds,
 *   (3) local markdown image paths produced by local automation (restricted allowlist).
 * - Optional: support "MEDIA:" outputs from the agent to send files back to Feishu
 *   with correct upload/send type mapping (avoids 230055).
 */

import * as Lark from '@larksuiteoapi/node-sdk';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

// Load .env automatically (so users don't need to export env vars manually).
// - Does NOT override existing process.env values.
// - Keeps this bridge dependency-free (no dotenv package).
loadDotEnvIfPresent();

function loadDotEnvIfPresent() {
  const candidates = [
    // cwd
    path.resolve(process.cwd(), '.env'),
    // script dir
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '.env'),
  ];

  for (const p of candidates) {
    try {
      if (!fs.existsSync(p)) continue;
      const raw = fs.readFileSync(p, 'utf8');
      for (const line of raw.split(/\r?\n/)) {
        const s = line.trim();
        if (!s || s.startsWith('#')) continue;
        const i = s.indexOf('=');
        if (i <= 0) continue;
        const k = s.slice(0, i).trim();
        const v = s.slice(i + 1).trim();
        if (!k) continue;
        if (process.env[k] == null) process.env[k] = v;
      }
      return;
    } catch {
      // ignore
    }
  }
}

// ─── Config ──────────────────────────────────────────────────────

const APP_ID = process.env.FEISHU_APP_ID;
const APP_SECRET_PATH = resolvePath(process.env.FEISHU_APP_SECRET_PATH || '~/.clawdbot/secrets/feishu_app_secret');
const CLAWDBOT_CONFIG_PATH = resolvePath(process.env.CLAWDBOT_CONFIG_PATH || '~/.clawdbot/clawdbot.json');
const CLAWDBOT_AGENT_ID = process.env.CLAWDBOT_AGENT_ID || 'main';
const THINKING_THRESHOLD_MS = Number(process.env.FEISHU_THINKING_THRESHOLD_MS ?? 2500);

// Local markdown media support (issue #3): allow reading ONLY under these dirs.
// Default supports the common local automation path: ~/.clawdbot/media
const ALLOWED_LOCAL_MEDIA_DIRS = (process.env.FEISHU_BRIDGE_ALLOWED_LOCAL_MEDIA_DIRS || '~/.clawdbot/media')
  .split(',')
  .map((s) => resolvePath(s.trim()))
  .filter(Boolean);

// Outbound media (agent → Feishu): allow sending files ONLY from these dirs.
// Default includes /tmp so tool-generated images can be sent.
const ALLOWED_OUTBOUND_MEDIA_DIRS = (
  process.env.FEISHU_BRIDGE_ALLOWED_OUTBOUND_MEDIA_DIRS || `~/.clawdbot/media,${os.tmpdir()},/tmp`
)
  .split(',')
  .map((s) => resolvePath(s.trim()))
  .filter(Boolean);

const MAX_LOCAL_FILE_MB = Number(process.env.FEISHU_BRIDGE_MAX_LOCAL_FILE_MB ?? 15);
const MAX_INBOUND_IMAGE_MB = Number(process.env.FEISHU_BRIDGE_MAX_INBOUND_IMAGE_MB ?? 12);
const MAX_INBOUND_FILE_MB = Number(process.env.FEISHU_BRIDGE_MAX_INBOUND_FILE_MB ?? 40);
const INBOUND_FILE_TTL_MIN = Number(process.env.FEISHU_BRIDGE_INBOUND_FILE_TTL_MIN ?? 60);
const MAX_ATTACHMENTS = Number(process.env.FEISHU_BRIDGE_MAX_ATTACHMENTS ?? 4);

const SELFTEST = process.argv.includes('--selftest') || process.env.FEISHU_BRIDGE_SELFTEST === '1';
const DEBUG = process.env.FEISHU_BRIDGE_DEBUG === '1';

// ─── Helpers ─────────────────────────────────────────────────────

function resolvePath(p) {
  return String(p || '').replace(/^~/, os.homedir());
}

function mustRead(filePath, label) {
  const resolved = resolvePath(filePath);
  if (!fs.existsSync(resolved)) {
    console.error(`[FATAL] ${label} not found: ${resolved}`);
    process.exit(1);
  }
  const val = fs.readFileSync(resolved, 'utf8').trim();
  if (!val) {
    console.error(`[FATAL] ${label} is empty: ${resolved}`);
    process.exit(1);
  }
  return val;
}

const uuid = () => crypto.randomUUID();

function toNodeReadableStream(maybeStream) {
  if (!maybeStream) return null;
  if (typeof maybeStream.pipe === 'function') return maybeStream; // Node stream
  // Web stream
  if (typeof maybeStream.getReader === 'function' && typeof Readable.fromWeb === 'function') {
    return Readable.fromWeb(maybeStream);
  }
  return null;
}

function truncate(s, max = 2000) {
  const str = String(s ?? '');
  if (str.length <= max) return str;
  return str.slice(0, max) + `…(truncated, ${str.length} chars)`;
}

function decodeHtmlEntities(s) {
  return String(s ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'");
}

/**
 * Normalize Feishu "text" payloads.
 * Some clients may send HTML-ish strings like <p>- 1</p><p>- 2</p>.
 */
function normalizeFeishuText(raw) {
  let t = String(raw ?? '');

  // Convert common HTML blocks to newlines
  t = t.replace(/<\s*br\s*\/?>/gi, '\n');
  t = t.replace(/<\s*\/p\s*>\s*<\s*p\s*>/gi, '\n');
  t = t.replace(/<\s*p\s*>/gi, '');
  t = t.replace(/<\s*\/p\s*>/gi, '');

  // Strip remaining tags
  t = t.replace(/<[^>]+>/g, '');

  t = decodeHtmlEntities(t);

  // Normalize newlines
  t = t.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  t = t.replace(/\n{3,}/g, '\n\n');

  // Fix Feishu list quirk: sometimes list marker and content are split into two lines.
  //   "-\n1" -> "- 1"
  //   "•\nfoo" -> "• foo"
  t = t.replace(/(^|\n)([-*•])\n(?=\S)/g, '$1$2 ');
  t = t.replace(/(^|\n)(\d+[\.|\)])\n(?=\S)/g, '$1$2 ');

  return t.trim();
}

function extLower(p) {
  return path.extname(p || '').toLowerCase().replace(/^\./, '');
}

function guessMimeByExt(p) {
  const e = extLower(p);
  if (e === 'png') return 'image/png';
  if (e === 'jpg' || e === 'jpeg') return 'image/jpeg';
  if (e === 'gif') return 'image/gif';
  if (e === 'webp') return 'image/webp';
  if (e === 'mp4') return 'video/mp4';
  if (e === 'mov') return 'video/quicktime';
  if (e === 'mp3') return 'audio/mpeg';
  if (e === 'wav') return 'audio/wav';
  if (e === 'm4a') return 'audio/mp4';
  if (e === 'opus') return 'audio/opus';
  return 'application/octet-stream';
}

function isPathInside(child, parent) {
  const rel = path.relative(parent, child);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function isAllowedLocalPath(filePath) {
  const p = path.resolve(filePath);
  return ALLOWED_LOCAL_MEDIA_DIRS.some((dir) => isPathInside(p, dir) || p === dir);
}

function isAllowedOutboundPath(filePath) {
  const p = path.resolve(filePath);
  return ALLOWED_OUTBOUND_MEDIA_DIRS.some((dir) => isPathInside(p, dir) || p === dir);
}

function scheduleCleanup(filePath, minutes = INBOUND_FILE_TTL_MIN) {
  const ms = Math.max(1, Number(minutes || 0)) * 60 * 1000;
  const t = setTimeout(() => {
    try { fs.unlinkSync(filePath); } catch {}
  }, ms);
  // Let Node exit even if the timer is pending.
  if (typeof t.unref === 'function') t.unref();
}

function looksLikeMediaRef(s) {
  const v = String(s || '').trim();
  if (!v) return false;
  if (/^data:[^;]+;base64,/i.test(v)) return true;
  if (/^https?:\/\//i.test(v)) return true;
  if (/^file:\/\//i.test(v)) return true;
  if (v.startsWith('/') && /\.(png|jpe?g|gif|webp|bmp|mp4|mov|mp3|wav|m4a|opus)$/i.test(v)) return true;
  if (/^MEDIA:\s*\S+/i.test(v)) return true;
  return false;
}

function extractMediaRefsDeep(value, limit = 8) {
  const out = [];
  const seen = new Set();
  const walk = (x, depth) => {
    if (out.length >= limit) return;
    if (depth > 4) return;

    if (typeof x === 'string') {
      if (looksLikeMediaRef(x)) {
        const m = /^MEDIA:\s*(\S+)/i.exec(x.trim());
        const ref = m ? m[1] : x.trim();
        if (!seen.has(ref)) {
          seen.add(ref);
          out.push(ref);
        }
      }
      return;
    }

    if (!x) return;
    if (Array.isArray(x)) {
      for (const it of x) walk(it, depth + 1);
      return;
    }

    if (typeof x === 'object') {
      for (const v of Object.values(x)) walk(v, depth + 1);
    }
  };

  walk(value, 0);
  return out;
}

function safeFileSizeOk(filePath) {
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile()) return { ok: false, reason: 'not a file' };
    const maxBytes = MAX_LOCAL_FILE_MB * 1024 * 1024;
    if (st.size > maxBytes) return { ok: false, reason: `too large (${st.size} bytes)` };
    return { ok: true, size: st.size };
  } catch (e) {
    return { ok: false, reason: e?.message || String(e) };
  }
}

function fileToDataUrl(filePath, mimeType) {
  const buf = fs.readFileSync(filePath);
  const b64 = buf.toString('base64');
  return `data:${mimeType};base64,${b64}`;
}

function isProbablyImagePath(p) {
  return /\.(png|jpg|jpeg|gif|webp|bmp)$/i.test(p);
}

function isProbablyVideoPath(p) {
  return /\.(mp4|mov|avi|mkv|webm)$/i.test(p);
}

function isProbablyAudioPath(p) {
  return /\.(opus|mp3|wav|m4a|aac|ogg)$/i.test(p);
}

function extractMarkdownLocalMediaPaths(text) {
  const t = String(text ?? '');
  const out = [];

  // Markdown image syntax: ![alt](path)
  // Note: we only care about absolute local paths or file:// URLs.
  const mdImageRe = /!\[[^\]]*\]\(([^)]+)\)/g;
  let m;
  while ((m = mdImageRe.exec(t))) {
    const raw = (m[1] || '').trim().replace(/^</, '').replace(/>$/, '');
    if (!raw) continue;
    if (raw.startsWith('file://')) out.push(raw.replace('file://', ''));
    else if (raw.startsWith('/')) out.push(raw);
    else if (raw.startsWith('~')) out.push(resolvePath(raw));
  }

  // Also support bare local paths (rare): /Users/.../.clawdbot/media/xxx.png or /tmp/xxx.png
  const barePathRe = /\/(Users|home|tmp)\/[^\s)]+\.(png|jpg|jpeg|gif|webp|bmp)/gi;
  while ((m = barePathRe.exec(t))) {
    out.push(m[0]);
  }

  // Dedup
  return [...new Set(out)];
}

function stripMarkdownLocalMediaRefs(text) {
  const t = String(text ?? '');
  // Remove markdown image refs and bare paths; keep text readable.
  return t
    .replace(/!\[[^\]]*\]\(([^)]+)\)/g, '[图片]')
    .replace(/\/(Users|home)\/[^\s)]+\.(png|jpg|jpeg|gif|webp|bmp)/gi, '[图片]')
    .trim();
}

function parseMediaLines(replyText) {
  const text = String(replyText ?? '');
  const lines = text.split(/\r?\n/);
  const media = [];
  const kept = [];

  const pushMedia = (raw) => {
    let u = String(raw || '').trim();
    if (!u) return;
    // Strip angle brackets and trailing punctuation.
    u = u.replace(/^</, '').replace(/>$/, '').replace(/[),.;，。；]+$/, '').trim();
    if (!u) return;
    media.push(u);
  };

  for (const line of lines) {
    // 1) Dedicated MEDIA line
    const m = line.match(/^\s*MEDIA\s*[:：]\s*(.+?)\s*$/i);
    if (m) {
      pushMedia(m[1]);
      continue;
    }

    // 2) Inline MEDIA tokens (some agents print "... MEDIA: /path.png" in the same line)
    const inlineRe = /MEDIA\s*[:：]\s*(\S+)/gi;
    let mm;
    let foundInline = false;
    while ((mm = inlineRe.exec(line))) {
      foundInline = true;
      pushMedia(mm[1]);
    }
    if (foundInline) {
      // keep the line but remove the MEDIA token chunk to avoid clutter
      kept.push(line.replace(inlineRe, '').trim());
      continue;
    }

    kept.push(line);
  }

  return { text: kept.join('\n').trim(), mediaUrls: [...new Set(media)] };
}

async function downloadUrlToTempFile(url) {
  const u = String(url);
  const ext = extLower(u) || 'bin';
  const tmp = path.join(os.tmpdir(), `feishu_bridge_${Date.now()}_${Math.random().toString(16).slice(2)}.${ext}`);

  const proto = u.startsWith('https') ? https : http;

  await new Promise((resolve, reject) => {
    const req = proto.get(u, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        const loc = res.headers.location;
        res.resume();
        if (!loc) return reject(new Error('Redirect without location header'));
        downloadUrlToTempFile(loc).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const out = fs.createWriteStream(tmp);
      pipeline(res, out).then(resolve).catch(reject);
    });
    req.on('error', reject);
  });

  return tmp;
}

function cleanupTempFile(filePath) {
  try {
    if (filePath && filePath.startsWith(os.tmpdir())) fs.unlinkSync(filePath);
  } catch {
    // ignore
  }
}

// ─── Load secrets & config ───────────────────────────────────────

if (SELFTEST) {
  await runSelfTest();
  process.exit(0);
}

if (!APP_ID) {
  console.error('[FATAL] FEISHU_APP_ID environment variable is required');
  process.exit(1);
}

const APP_SECRET = mustRead(APP_SECRET_PATH, 'Feishu App Secret');
const clawdConfig = JSON.parse(mustRead(CLAWDBOT_CONFIG_PATH, 'Clawdbot config'));

const GATEWAY_PORT = clawdConfig?.gateway?.port || 18789;
const GATEWAY_TOKEN = clawdConfig?.gateway?.auth?.token;

if (!GATEWAY_TOKEN) {
  console.error('[FATAL] gateway.auth.token missing in Clawdbot config');
  process.exit(1);
}

// ─── Feishu SDK setup ────────────────────────────────────────────

const sdkConfig = {
  appId: APP_ID,
  appSecret: APP_SECRET,
  domain: Lark.Domain.Feishu,
  appType: Lark.AppType.SelfBuild,
};

const client = new Lark.Client(sdkConfig);
const wsClient = new Lark.WSClient({ ...sdkConfig, loggerLevel: Lark.LoggerLevel.info });

// ─── Dedup (Feishu may deliver the same event more than once) ────

const seen = new Map();
const SEEN_TTL_MS = 10 * 60 * 1000;

function isDuplicate(messageId) {
  const now = Date.now();
  for (const [k, ts] of seen) {
    if (now - ts > SEEN_TTL_MS) seen.delete(k);
  }
  if (!messageId) return false;
  if (seen.has(messageId)) return true;
  seen.set(messageId, now);
  return false;
}

// ─── Talk to Clawdbot Gateway ────────────────────────────────────

async function askClawdbot({ text, sessionKey, attachments = [] }) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${GATEWAY_PORT}`);
    let runId = null;
    let buf = '';
    let mediaUrls = [];

    const close = () => {
      try {
        ws.close();
      } catch {}
    };

    ws.on('error', (e) => {
      close();
      reject(e);
    });

    ws.on('message', (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }

      if (msg.type === 'event' && msg.event === 'connect.challenge') {
        ws.send(
          JSON.stringify({
            type: 'req',
            id: 'connect',
            method: 'connect',
            params: {
              minProtocol: 3,
              maxProtocol: 3,
              client: { id: 'gateway-client', version: '0.3.0', platform: 'macos', mode: 'backend' },
              role: 'operator',
              scopes: ['operator.read', 'operator.write'],
              auth: { token: GATEWAY_TOKEN },
              locale: 'zh-CN',
              userAgent: 'feishu-clawdbot-bridge',
            },
          }),
        );
        return;
      }

      if (msg.type === 'res' && msg.id === 'connect') {
        if (!msg.ok) {
          close();
          reject(new Error(msg.error?.message || 'connect failed'));
          return;
        }

        const params = {
          message: text,
          agentId: CLAWDBOT_AGENT_ID,
          sessionKey,
          deliver: false,
          // Help the agent return media in a way the bridge can forward.
          extraSystemPrompt:
            'When you generate images/files, always include one or more standalone lines like:\nMEDIA: <absolute_file_path_or_url>\nIf you cannot generate or attach media, say so explicitly.',
          idempotencyKey: uuid(),
        };

        if (Array.isArray(attachments) && attachments.length > 0) {
          params.attachments = attachments;
        }

        ws.send(
          JSON.stringify({
            type: 'req',
            id: 'agent',
            method: 'agent',
            params,
          }),
        );
        return;
      }

      if (msg.type === 'res' && msg.id === 'agent') {
        if (!msg.ok) {
          close();
          reject(new Error(msg.error?.message || 'agent error'));
          return;
        }
        if (msg.payload?.runId) runId = msg.payload.runId;
        return;
      }

      if (msg.type === 'event' && msg.event === 'agent') {
        const p = msg.payload;
        if (!p || (runId && p.runId !== runId)) return;

        // Capture media outputs from ANY stream (assistant/tool/etc).
        // Some tools return media URLs without printing "MEDIA:" lines.
        {
          const d = p.data || {};
          if (typeof d.mediaUrl === 'string' && d.mediaUrl.trim()) {
            mediaUrls.push(d.mediaUrl.trim());
          }
          if (Array.isArray(d.mediaUrls)) {
            for (const u of d.mediaUrls) {
              if (typeof u === 'string' && u.trim()) mediaUrls.push(u.trim());
            }
          }

          // Ultra-defensive: some tools embed media refs deeply.
          const deep = extractMediaRefsDeep(d, 8);
          if (deep.length > 0) mediaUrls.push(...deep);

          if (DEBUG) {
            const hasDirect = Boolean(d.mediaUrl || (Array.isArray(d.mediaUrls) && d.mediaUrls.length));
            const hasDeep = deep.length > 0;
            if (hasDirect || hasDeep) {
              console.log(`[DEBUG] agent event media: stream=${p.stream} direct=${hasDirect} deep=${JSON.stringify(deep)}`);
            }
          }
        }

        if (p.stream === 'assistant') {
          const d = p.data || {};

          // text stream
          if (typeof d.text === 'string') buf = d.text;
          else if (typeof d.delta === 'string') buf += d.delta;
          return;
        }

        if (p.stream === 'lifecycle') {
          if (p.data?.phase === 'end') {
            close();
            mediaUrls = [...new Set(mediaUrls)];
            if (DEBUG) {
              console.log(`[DEBUG] agent run end: runId=${runId || '-'} textLen=${(buf || '').length} mediaCount=${mediaUrls.length}`);
              if (mediaUrls.length) console.log(`[DEBUG] agent mediaUrls: ${mediaUrls.slice(0, 6).join(' | ')}`);
            }
            resolve({ text: (buf || '').trim(), mediaUrls });
          }
          if (p.data?.phase === 'error') {
            close();
            reject(new Error(p.data?.message || 'agent error'));
          }
        }
      }
    });
  });
}

// ─── Feishu message parsing ─────────────────────────────────────

function shouldRespondInGroup(text, mentions) {
  if (mentions.length > 0) return true;
  const t = text.toLowerCase();
  if (/[？?]$/.test(text)) return true;
  if (/\b(why|how|what|when|where|who|help)\b/.test(t)) return true;
  const verbs = ['帮', '麻烦', '请', '能否', '可以', '解释', '看看', '排查', '分析', '总结', '写', '改', '修', '查', '对比', '翻译'];
  if (verbs.some((k) => text.includes(k))) return true;
  if (/^(alen|clawdbot|bot|助手|智能体)[\s,:，：]/i.test(text)) return true;
  return false;
}

function extractFromPostJson(postJson) {
  const lines = [];
  const imageKeys = [];

  const pushLine = (s) => {
    const v = String(s ?? '').trimEnd();
    if (v.trim()) lines.push(v);
  };

  const inline = (node) => {
    if (!node) return '';
    if (Array.isArray(node)) return node.map(inline).join('');
    if (typeof node !== 'object') return '';

    const tag = node.tag;
    if (typeof tag === 'string') {
      if (tag === 'text') return String(node.text ?? '');
      if (tag === 'a') return String(node.text ?? node.href ?? '');
      if (tag === 'at') return node.user_name ? `@${node.user_name}` : '@';
      if (tag === 'md') return String(node.text ?? '');
      if (tag === 'img') {
        if (node.image_key) imageKeys.push(String(node.image_key));
        return '[图片]';
      }
      if (tag === 'file') return '[文件]';
      if (tag === 'media') return '[视频]';
      if (tag === 'hr') return '\n';
      if (tag === 'code_block') {
        const lang = String(node.language || '').trim();
        const code = String(node.text || '');
        return `\n\n\
\`\`\`${lang ? ` ${lang}` : ''}\n${code}\n\`\`\`\n\n`;
      }
    }

    // Fallback: traverse children to avoid dropping content when Feishu changes structure.
    let acc = '';
    for (const v of Object.values(node)) {
      if (v && (typeof v === 'object' || Array.isArray(v))) acc += inline(v);
    }
    return acc;
  };

  if (postJson?.title) pushLine(normalizeFeishuText(postJson.title));

  const content = postJson?.content;
  if (Array.isArray(content)) {
    for (const paragraph of content) {
      // In Feishu post, each paragraph is usually an array of inline nodes.
      if (Array.isArray(paragraph)) {
        const joined = paragraph.map(inline).join('');
        const normalized = normalizeFeishuText(joined);
        if (normalized) pushLine(normalized);
      } else {
        const normalized = normalizeFeishuText(inline(paragraph));
        if (normalized) pushLine(normalized);
      }
    }
  } else if (content) {
    const normalized = normalizeFeishuText(inline(content));
    if (normalized) pushLine(normalized);
  }

  const text = lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();

  return { text, imageKeys: [...new Set(imageKeys)] };
}


async function downloadFeishuImageAsDataUrl(messageId, imageKey) {
  const tmp = path.join(os.tmpdir(), `feishu_recv_${Date.now()}_${Math.random().toString(16).slice(2)}.png`);
  try {
    if (DEBUG) console.log(`[DEBUG] Downloading image: messageId=${messageId}, imageKey=${imageKey}`);
    const response = await client.im.messageResource.get({
      path: { message_id: messageId, file_key: imageKey },
      params: { type: 'image' },
    });

    // Debug: log response structure
    const responseType = typeof response;
    const responseKeys = response && typeof response === 'object' ? Object.keys(response) : [];
    if (DEBUG) console.log(`[DEBUG] Image response: type=${responseType}, keys=${responseKeys.join(',')}`);
    if (response && response.data) {
      const dataType = typeof response.data;
      const dataKeys = response.data && typeof response.data === 'object' ? Object.keys(response.data) : [];
      if (DEBUG) console.log(`[DEBUG] response.data: type=${dataType}, keys=${dataKeys.join(',')}`);
    }

    // SDK may return stream/buffer or wrap it inside { data: ... }
    const data = response;
    const payload = (data && typeof data === 'object' && 'data' in data) ? data.data : data;

    // Newer SDK versions return a "response-like" object with helpers.
    if (payload && typeof payload.writeFile === 'function') {
      await payload.writeFile(tmp);
    } else if (payload && typeof payload.getReadableStream === 'function') {
      const rs = payload.getReadableStream();
      const nodeRs = toNodeReadableStream(rs);
      if (!nodeRs) throw new Error('getReadableStream() returned non-stream');
      const out = fs.createWriteStream(tmp);
      await pipeline(nodeRs, out);
    } else if (payload && typeof payload.pipe === 'function') {
      const out = fs.createWriteStream(tmp);
      await pipeline(payload, out);
    } else if (data && data.data && typeof data.data === 'object' && typeof data.data.pipe === 'function') {
      // Some SDK versions nest the stream deeper
      const out = fs.createWriteStream(tmp);
      await pipeline(data.data, out);
    } else if (Buffer.isBuffer(payload)) {
      fs.writeFileSync(tmp, payload);
    } else if (payload instanceof ArrayBuffer) {
      fs.writeFileSync(tmp, Buffer.from(payload));
    } else if (ArrayBuffer.isView(payload)) {
      fs.writeFileSync(tmp, Buffer.from(payload.buffer));
    } else {
      const k = data && typeof data === 'object' ? Object.keys(data).join(',') : '';
      throw new Error(`Unexpected response type: ${typeof data}${k ? ` (keys: ${k})` : ''}`);
    }

    // Size guard: base64 data URLs explode in size; avoid choking the gateway.
    const st = fs.statSync(tmp);
    if (DEBUG) console.log(`[DEBUG] Image downloaded: ${st.size} bytes -> ${tmp}`);
    const maxBytes = MAX_INBOUND_IMAGE_MB * 1024 * 1024;
    if (st.size > maxBytes) {
      throw new Error(`Image too large (${st.size} bytes > ${maxBytes})`);
    }

    return fileToDataUrl(tmp, 'image/png');
  } finally {
    cleanupTempFile(tmp);
  }
}

async function downloadFeishuFileToPath(messageId, fileKey, fileName = 'file.bin', type = 'file') {
  const ext = path.extname(fileName || '') || '.bin';
  const tmp = path.join(
    os.tmpdir(),
    `feishu_recv_${Date.now()}_${Math.random().toString(16).slice(2)}${ext}`,
  );

  const response = await client.im.messageResource.get({
    path: { message_id: messageId, file_key: fileKey },
    params: { type },
  });

  const data = response;
  const payload = (data && typeof data === 'object' && 'data' in data) ? data.data : data;

  if (payload && typeof payload.writeFile === 'function') {
    await payload.writeFile(tmp);
  } else if (payload && typeof payload.getReadableStream === 'function') {
    const rs = payload.getReadableStream();
    const nodeRs = toNodeReadableStream(rs);
    if (!nodeRs) throw new Error('getReadableStream() returned non-stream');
    const out = fs.createWriteStream(tmp);
    await pipeline(nodeRs, out);
  } else if (payload && typeof payload.pipe === 'function') {
    const out = fs.createWriteStream(tmp);
    await pipeline(payload, out);
  } else if (data && data.data && typeof data.data === 'object' && typeof data.data.pipe === 'function') {
    const out = fs.createWriteStream(tmp);
    await pipeline(data.data, out);
  } else if (Buffer.isBuffer(payload)) {
    fs.writeFileSync(tmp, payload);
  } else if (payload instanceof ArrayBuffer) {
    fs.writeFileSync(tmp, Buffer.from(payload));
  } else if (ArrayBuffer.isView(payload)) {
    fs.writeFileSync(tmp, Buffer.from(payload.buffer));
  } else {
    const k = data && typeof data === 'object' ? Object.keys(data).join(',') : '';
    throw new Error(`Unexpected file response type: ${typeof data}${k ? ` (keys: ${k})` : ''}`);
  }

  // Size guard
  const st = fs.statSync(tmp);
  const maxBytes = MAX_INBOUND_FILE_MB * 1024 * 1024;
  if (st.size > maxBytes) {
    // Keep the file from accumulating.
    try { fs.unlinkSync(tmp); } catch {}
    throw new Error(`File too large (${st.size} bytes > ${maxBytes})`);
  }

  // Keep the downloaded file alive long enough for the agent to use it.
  scheduleCleanup(tmp, INBOUND_FILE_TTL_MIN);

  return tmp;
}

async function buildInboundFromFeishuMessage(message) {
  const messageId = message?.message_id;
  const messageType = message?.message_type;
  const rawContent = message?.content;

  const out = {
    text: '',
    attachments: [],
    fallback: '',
  };

  out.fallback = `【Feishu消息】id=${messageId || '-'} type=${messageType}\ncontent=${truncate(rawContent, 1200)}`;

  if (!messageType || !rawContent) return out;

  // 1) text
  if (messageType === 'text') {
    try {
      const parsed = JSON.parse(rawContent);
      out.text = normalizeFeishuText(parsed?.text ?? '');
    } catch {
      out.text = '';
    }
  }

  // 2) post (rich text)
  if (messageType === 'post') {
    try {
      const parsed = JSON.parse(rawContent);
      const { text, imageKeys } = extractFromPostJson(parsed);
      out.text = text;

      // Download embedded images (best-effort)
      if (messageId && imageKeys.length > 0) {
        for (const k of imageKeys.slice(0, MAX_ATTACHMENTS)) {
          try {
            const dataUrl = await downloadFeishuImageAsDataUrl(messageId, k);
            out.attachments.push({ type: 'image', content: dataUrl, mimeType: 'image/png', fileName: 'feishu.png' });
          } catch (e) {
            // keep going
            console.error(`[WARN] post image download failed: messageId=${messageId} imageKey=${k} err=${e?.message || String(e)}`);
          }
        }
      }
    } catch (e) {
      out.text = '';
      console.error(`[WARN] post parse failed: ${e?.message || String(e)}`);
    }
  }

  // 3) image
  if (messageType === 'image') {
    try {
      const parsed = JSON.parse(rawContent);
      const imageKey = parsed?.image_key;
      if (imageKey && messageId) {
        const dataUrl = await downloadFeishuImageAsDataUrl(messageId, imageKey);
        out.attachments.push({ type: 'image', content: dataUrl, mimeType: 'image/png', fileName: 'feishu.png' });
        out.text = '[图片]';
      }
    } catch (e) {
      // Don't drop the message; keep a minimal placeholder.
      out.text = '[图片]';
      console.error(`[WARN] image parse/download failed: messageId=${messageId} err=${e?.message || String(e)}`);
    }
  }

  // 4) media (video)
  if (messageType === 'media') {
    try {
      const parsed = JSON.parse(rawContent);
      const fileKey = parsed?.file_key;
      const fileName = parsed?.file_name || 'video.bin';
      const duration = parsed?.duration;
      const thumbKey = parsed?.image_key;

      out.text = `[视频] ${fileName}${duration ? ` (${duration}ms)` : ''}`;

      // Best-effort: thumbnail
      if (thumbKey && messageId) {
        try {
          const thumbUrl = await downloadFeishuImageAsDataUrl(messageId, thumbKey);
          out.attachments.push({ type: 'image', content: thumbUrl, mimeType: 'image/png', fileName: 'feishu-thumb.png' });
        } catch (e) {
          console.error(`[WARN] media thumbnail download failed: messageId=${messageId} imageKey=${thumbKey} err=${e?.message || String(e)}`);
        }
      }

      // Best-effort: download the video file so the agent can access it.
      if (fileKey && messageId) {
        try {
          const fp = await downloadFeishuFileToPath(messageId, fileKey, fileName, 'file');
          // NOTE: Gateway agent attachments currently only support image base64 content.
          // For videos, pass the local path via text so the agent can decide how to use it.
          out.text += `\n\n[附件路径] file://${fp}`;
        } catch (e) {
          console.error(`[WARN] media download failed: messageId=${messageId} fileKey=${fileKey} err=${e?.message || String(e)}`);
        }
      }
    } catch (e) {
      out.text = out.text || '[视频]';
      console.error(`[WARN] media parse failed: ${e?.message || String(e)}`);
    }
  }

  // 5) file
  if (messageType === 'file') {
    try {
      const parsed = JSON.parse(rawContent);
      const fileKey = parsed?.file_key;
      const fileName = parsed?.file_name || 'file.bin';
      out.text = `[文件] ${fileName}`;

      if (fileKey && messageId) {
        try {
          const fp = await downloadFeishuFileToPath(messageId, fileKey, fileName, 'file');
          // NOTE: Gateway agent attachments currently only support image base64 content.
          // For files, pass the local path via text so the agent can decide how to use it.
          out.text += `\n\n[附件路径] file://${fp}`;
        } catch (e) {
          console.error(`[WARN] file download failed: messageId=${messageId} fileKey=${fileKey} err=${e?.message || String(e)}`);
        }
      }
    } catch (e) {
      out.text = out.text || '[文件]';
      console.error(`[WARN] file parse failed: ${e?.message || String(e)}`);
    }
  }

  // 6) audio
  if (messageType === 'audio') {
    try {
      const parsed = JSON.parse(rawContent);
      const fileKey = parsed?.file_key;
      const fileName = parsed?.file_name || 'audio.opus';
      out.text = `[语音] ${fileName}`;

      if (fileKey && messageId) {
        try {
          const fp = await downloadFeishuFileToPath(messageId, fileKey, fileName, 'file');
          // NOTE: Gateway agent attachments currently only support image base64 content.
          // For audio, pass the local path via text so the agent can decide how to use it.
          out.text += `\n\n[附件路径] file://${fp}`;
        } catch (e) {
          console.error(`[WARN] audio download failed: messageId=${messageId} fileKey=${fileKey} err=${e?.message || String(e)}`);
        }
      }
    } catch (e) {
      out.text = out.text || '[语音]';
      console.error(`[WARN] audio parse failed: ${e?.message || String(e)}`);
    }
  }

  // Local markdown images (issue #3): if text includes local paths, attach them.
  if (out.text) {
    const localPaths = extractMarkdownLocalMediaPaths(out.text).slice(0, MAX_ATTACHMENTS - out.attachments.length);
    for (const p of localPaths) {
      try {
        const fp = path.resolve(p);
        if (!isAllowedLocalPath(fp)) continue;
        const ok = safeFileSizeOk(fp);
        if (!ok.ok) continue;
        if (!isProbablyImagePath(fp)) continue;
        const mime = guessMimeByExt(fp);
        const dataUrl = fileToDataUrl(fp, mime);
        out.attachments.push({ type: 'image', content: dataUrl, mimeType: mime, fileName: path.basename(fp) });
      } catch (e) {
        console.error(`[WARN] local image attach failed: ${e?.message || String(e)}`);
      }
    }
    out.text = stripMarkdownLocalMediaRefs(out.text);
  }

  // Ensure we never silently drop: if still empty, use fallback.
  if (!out.text && out.attachments.length > 0) out.text = '[附件]';
  if (!out.text) out.text = out.fallback;

  // Hard cap
  if (out.attachments.length > MAX_ATTACHMENTS) out.attachments = out.attachments.slice(0, MAX_ATTACHMENTS);

  return out;
}

// ─── Feishu sending (text + media) ──────────────────────────────

async function sendText(chatId, text) {
  return client.im.v1.message.create({
    params: { receive_id_type: 'chat_id' },
    data: { receive_id: chatId, msg_type: 'text', content: JSON.stringify({ text }) },
  });
}

async function updateTextMessage(messageId, text) {
  return client.im.v1.message.update({
    path: { message_id: messageId },
    data: { msg_type: 'text', content: JSON.stringify({ text }) },
  });
}

async function deleteMessage(messageId) {
  return client.im.v1.message.delete({ path: { message_id: messageId } });
}

async function uploadAndSendMedia(chatId, mediaUrlOrPath, captionText) {
  let tempPath = null;
  let localPath = null;

  try {
    const raw = String(mediaUrlOrPath || '').trim();
    if (!raw) return;

    if (raw.startsWith('file://')) {
      localPath = raw.replace('file://', '');
    } else if (raw.startsWith('~')) {
      localPath = resolvePath(raw);
    } else if (raw.startsWith('/')) {
      localPath = raw;
    } else if (raw.startsWith('http://') || raw.startsWith('https://')) {
      tempPath = await downloadUrlToTempFile(raw);
      localPath = tempPath;
    } else if (raw.startsWith('data:')) {
      // data:<mime>;base64,<payload>
      const m = raw.match(/^data:([^;]+);base64,(.*)$/);
      if (!m) {
        await sendText(chatId, captionText ? `${captionText}\n${raw}` : raw);
        return;
      }
      const mime = m[1];
      const b64 = m[2];
      const ext = mime.includes('png')
        ? 'png'
        : mime.includes('jpeg') || mime.includes('jpg')
          ? 'jpg'
          : mime.includes('webp')
            ? 'webp'
            : 'bin';
      tempPath = path.join(os.tmpdir(), `feishu_out_${Date.now()}_${Math.random().toString(16).slice(2)}.${ext}`);
      fs.writeFileSync(tempPath, Buffer.from(b64, 'base64'));
      localPath = tempPath;
    } else {
      // Unknown scheme; just send as text.
      await sendText(chatId, captionText ? `${captionText}\n${raw}` : raw);
      return;
    }

    const p = path.resolve(localPath);
    const mime = guessMimeByExt(p);

    // Local safety for absolute paths.
    // IMPORTANT: only allow sending local files from an allowlist to avoid accidental exfil.
    if (!tempPath && p.startsWith('/')) {
      if (!isAllowedOutboundPath(p)) {
        if (DEBUG) console.log(`[DEBUG] outbound blocked by allowlist: ${p}`);
        // Don't spam users in normal mode; just skip this media.
        if (DEBUG) {
          await sendText(chatId, captionText ? `${captionText}\n（拒绝发送非白名单路径的本地文件）` : '（拒绝发送非白名单路径的本地文件）');
        }
        return;
      }
      const ok = safeFileSizeOk(p);
      if (!ok.ok) {
        if (DEBUG) {
          await sendText(chatId, captionText ? `${captionText}\n（附件过大或不可读：${ok.reason}）` : `（附件过大或不可读：${ok.reason}）`);
        }
        return;
      }
    }

    // Map types carefully to avoid Feishu error 230055.
    if (isProbablyImagePath(p)) {
      const res = await client.im.image.create({
        data: { image_type: 'message', image: fs.createReadStream(p) },
      });
      const imageKey = res?.data?.image_key || res?.image_key;
      if (!imageKey) throw new Error('upload image failed');

      await client.im.v1.message.create({
        params: { receive_id_type: 'chat_id' },
        data: { receive_id: chatId, msg_type: 'image', content: JSON.stringify({ image_key: imageKey }) },
      });

      if (captionText?.trim()) await sendText(chatId, captionText.trim());
      return;
    }

    if (isProbablyVideoPath(p) && extLower(p) === 'mp4') {
      const res = await client.im.file.create({
        data: { file_type: 'mp4', file_name: path.basename(p), file: fs.createReadStream(p) },
      });
      const fileKey = res?.data?.file_key || res?.file_key;
      if (!fileKey) throw new Error('upload mp4 failed');

      // Important: msg_type must be "media" when file_type is mp4.
      await client.im.v1.message.create({
        params: { receive_id_type: 'chat_id' },
        data: { receive_id: chatId, msg_type: 'media', content: JSON.stringify({ file_key: fileKey }) },
      });

      if (captionText?.trim()) await sendText(chatId, captionText.trim());
      return;
    }

    // Audio: Feishu audio messages require opus; otherwise send as file.
    if (isProbablyAudioPath(p) && extLower(p) === 'opus') {
      const res = await client.im.file.create({
        data: { file_type: 'opus', file_name: path.basename(p), file: fs.createReadStream(p) },
      });
      const fileKey = res?.data?.file_key || res?.file_key;
      if (!fileKey) throw new Error('upload opus failed');

      await client.im.v1.message.create({
        params: { receive_id_type: 'chat_id' },
        data: { receive_id: chatId, msg_type: 'audio', content: JSON.stringify({ file_key: fileKey }) },
      });

      if (captionText?.trim()) await sendText(chatId, captionText.trim());
      return;
    }

    // Default: send as file (stream)
    const res = await client.im.file.create({
      data: { file_type: 'stream', file_name: path.basename(p), file: fs.createReadStream(p) },
    });
    const fileKey = res?.data?.file_key || res?.file_key;
    if (!fileKey) throw new Error('upload file failed');

    await client.im.v1.message.create({
      params: { receive_id_type: 'chat_id' },
      data: { receive_id: chatId, msg_type: 'file', content: JSON.stringify({ file_key: fileKey }) },
    });

    if (captionText?.trim()) await sendText(chatId, captionText.trim());
  } finally {
    if (tempPath) cleanupTempFile(tempPath);
  }
}

// ─── Message handler ─────────────────────────────────────────────

const dispatcher = new Lark.EventDispatcher({}).register({
  'im.message.receive_v1': async (data) => {
    try {
      const { message, sender } = data || {};
      const chatId = message?.chat_id;
      const messageId = message?.message_id;
      const chatType = message?.chat_type;
      const senderId = sender?.sender_id?.open_id || '';

      if (!chatId || !messageId) return;
      if (isDuplicate(messageId)) return;
      if (!message?.content) return;

      const inbound = await buildInboundFromFeishuMessage(message);
      let text = inbound.text;
      const attachments = inbound.attachments;

      // Group chat: respond only when needed.
      if (chatType === 'group') {
        const mentions = Array.isArray(message?.mentions) ? message.mentions : [];
        const hasAttachment = attachments.length > 0;
        const mentioned = mentions.length > 0;

        // Remove @_user_X placeholders for routing decisions.
        const cleaned = (text || '').replace(/@_user_\d+\s*/g, '').trim();
        const decisionText = cleaned.startsWith('【Feishu消息】') ? '' : cleaned;

        // For attachment-only messages in groups: require @ mention.
        if (hasAttachment && !mentioned && (!decisionText || decisionText === '[图片]' || decisionText === '[附件]')) return;

        // For pure text: apply the normal intent filter.
        if (!hasAttachment && (!decisionText || !shouldRespondInGroup(decisionText, mentions))) return;

        // Keep the cleaned text (so the agent doesn't see @_user_X noise)
        text = cleaned;
      }

      // Better session key isolation: p2p by sender, group by chat.
      const sessionKey = `feishu:${chatType === 'p2p' ? senderId : chatId}`;

      // Process asynchronously
      setImmediate(async () => {
        let placeholderId = '';
        let done = false;

        const timer =
          THINKING_THRESHOLD_MS > 0
            ? setTimeout(async () => {
                if (done) return;
                try {
                  const res = await sendText(chatId, '正在思考…');
                  placeholderId = res?.data?.message_id || '';
                } catch {
                  // ignore
                }
              }, THINKING_THRESHOLD_MS)
            : null;

        let replyText = '';
        let mediaUrls = [];
        try {
          const r = await askClawdbot({ text, sessionKey, attachments });
          if (typeof r === 'string') {
            replyText = r;
          } else {
            replyText = String(r?.text ?? '');
            if (Array.isArray(r?.mediaUrls)) {
              mediaUrls = r.mediaUrls
                .filter((u) => typeof u === 'string' && u.trim())
                .map((u) => u.trim());
            }
          }
        } catch (e) {
          replyText = `（系统出错）${e?.message || String(e)}`;
        } finally {
          done = true;
          if (timer) clearTimeout(timer);
        }

        // Support agent-produced media outputs
        // 1) structured mediaUrls from the gateway stream
        // 2) explicit MEDIA: lines in text
        // 3) markdown local image refs like ![](/tmp/x.png)
        const parsed = parseMediaLines(replyText);
        replyText = parsed.text;
        mediaUrls = mediaUrls.concat(parsed.mediaUrls || []);

        const mdPaths = extractMarkdownLocalMediaPaths(replyText);
        if (mdPaths.length > 0) {
          for (const pth of mdPaths) {
            const fp = path.resolve(pth);
            if (isAllowedOutboundPath(fp)) mediaUrls.push(fp);
          }
          replyText = stripMarkdownLocalMediaRefs(replyText);
        }

        mediaUrls = [...new Set(mediaUrls)].slice(0, 4);

        const trimmedText = (replyText || '').trim();
        if ((!trimmedText || trimmedText === 'NO_REPLY' || trimmedText.endsWith('NO_REPLY')) && mediaUrls.length === 0) {
          if (placeholderId) {
            try {
              await deleteMessage(placeholderId);
            } catch {}
          }
          return;
        }

        if (trimmedText.endsWith('NO_REPLY')) {
          replyText = trimmedText.replace(/\s*NO_REPLY\s*$/g, '').trim();
        }

        try {
          if (mediaUrls.length > 0) {
            if (placeholderId) {
              try {
                await deleteMessage(placeholderId);
              } catch {}
              placeholderId = '';
            }

            // Send each media (best-effort), then remaining text.
            for (const u of mediaUrls.slice(0, 4)) {
              await uploadAndSendMedia(chatId, u, undefined);
            }
            if (replyText?.trim()) {
              await sendText(chatId, replyText.trim());
            }
            return;
          }

          if (placeholderId) {
            try {
              await updateTextMessage(placeholderId, replyText);
              return;
            } catch {
              // fall through
            }
          }

          await sendText(chatId, replyText);
        } catch (err) {
          // Last resort: try to clean placeholder and send an error message.
          if (placeholderId) {
            try {
              await deleteMessage(placeholderId);
            } catch {}
          }
          try {
            await sendText(chatId, `（发送失败）${err instanceof Error ? err.message : String(err)}`);
          } catch {}
        }
      });
    } catch (e) {
      console.error('[ERROR] message handler:', e);
    }
  },
});

// ─── Start ───────────────────────────────────────────────────────

wsClient.start({ eventDispatcher: dispatcher });
console.log(`[OK] Feishu bridge started (appId=${APP_ID})`);
console.log(`[OK] Allowed local media dirs: ${ALLOWED_LOCAL_MEDIA_DIRS.join(', ') || '(none)'}`);

// ─── Self-test ───────────────────────────────────────────────────

async function runSelfTest() {
  const ok = (name, cond) => {
    if (!cond) throw new Error(`Selftest failed: ${name}`);
    console.log(`[OK] ${name}`);
  };

  // 1) post with list-like text structure (simulate nested arrays)
  const postExample = {
    title: '标题',
    content: [
      [
        { tag: 'text', text: '1. item1' },
        { tag: 'text', text: '2. item2' },
      ],
      [
        { tag: 'a', text: 'link', href: 'https://example.com' },
      ],
    ],
  };

  const ex1 = extractFromPostJson(postExample);
  ok('post extract text not empty', ex1.text.includes('item1') && ex1.text.includes('link'));

  // 2) markdown local image path extraction
  const md = '看看这张图 ![x](/Users/me/.clawdbot/media/a.png)';
  const paths = extractMarkdownLocalMediaPaths(md);
  ok('markdown local path parsed', paths.length === 1 && paths[0].includes('.clawdbot/media/a.png'));
  ok('markdown local path stripped', stripMarkdownLocalMediaRefs(md).includes('[图片]'));

  // 3) MEDIA line parsing
  const r = parseMediaLines('hello\nMEDIA: /tmp/a.mp4\nworld');
  ok('MEDIA parsed', r.mediaUrls.length === 1 && r.text.includes('hello') && r.text.includes('world'));

  console.log('[OK] Selftests finished');
}
