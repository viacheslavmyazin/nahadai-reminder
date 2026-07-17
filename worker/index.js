let jwksCache;
let jwksCachedAt = 0;

const SESSION_TTL = 365 * 24 * 60 * 60 * 1000;
const FLOW_TTL = 10 * 60 * 1000;
const LOGIN_CODE_TTL = 5 * 60 * 1000;

function corsHeaders(origin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "cache-control": "no-store",
    vary: "Origin",
  };
}

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders(origin),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function originFor(request, env) {
  const origin = request.headers.get("origin") || "";
  if (!env.ALLOWED_ORIGIN || env.ALLOWED_ORIGIN === "*") return "*";
  return origin === env.ALLOWED_ORIGIN ? origin : "";
}

function appUrl(env) {
  return env.APP_URL || "https://viacheslavmyazin.github.io/nahadai-reminder/";
}

function callbackUrl(request) {
  return new URL("/api/auth/telegram/callback", request.url).toString();
}

function randomToken(bytes = 32) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return bytesToBase64Url(value);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value)));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function telegramKeys() {
  if (jwksCache && Date.now() - jwksCachedAt < 60 * 60 * 1000) return jwksCache;
  const response = await fetch("https://oauth.telegram.org/.well-known/jwks.json");
  if (!response.ok) throw new Error("Telegram JWKS unavailable");
  jwksCache = await response.json();
  jwksCachedAt = Date.now();
  return jwksCache;
}

async function verifyTelegramIdToken(token, env, expectedNonce) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid ID token");

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  if (header.alg !== "RS256" || !header.kid) throw new Error("Unsupported ID token");

  const jwks = await telegramKeys();
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error("Signing key not found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!verified) throw new Error("Invalid ID token signature");

  const now = Math.floor(Date.now() / 1000);
  const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== "https://oauth.telegram.org") throw new Error("Invalid issuer");
  if (!audience.map(String).includes(String(env.TELEGRAM_CLIENT_ID))) throw new Error("Invalid audience");
  if (!payload.exp || payload.exp <= now) throw new Error("Expired ID token");
  if (payload.iat && payload.iat > now + 300) throw new Error("Invalid issued-at time");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("Invalid nonce");
  return payload;
}

function redirectToApp(env, key, value) {
  const target = new URL(appUrl(env));
  if (key && value) target.searchParams.set(key, value);
  return Response.redirect(target.toString(), 302);
}

async function startLogin(request, env) {
  if (!env.TELEGRAM_CLIENT_ID || !env.TELEGRAM_CLIENT_SECRET) {
    return new Response("Telegram Login is not configured", { status: 503 });
  }

  const state = randomToken(24);
  const verifier = randomToken(48);
  const nonce = randomToken(24);
  const challenge = await sha256(verifier);
  const expiresAt = Date.now() + FLOW_TTL;

  await env.DB.prepare(
    "INSERT INTO auth_flows (state, verifier, nonce, expires_at) VALUES (?, ?, ?, ?)",
  ).bind(state, verifier, nonce, expiresAt).run();

  const params = new URLSearchParams({
    client_id: String(env.TELEGRAM_CLIENT_ID),
    redirect_uri: callbackUrl(request),
    response_type: "code",
    scope: "openid profile telegram:bot_access",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return Response.redirect(`https://oauth.telegram.org/auth?${params}`, 302);
}

async function finishLogin(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  if (error) return redirectToApp(env, "auth_error", error);
  if (!code || !state) return redirectToApp(env, "auth_error", "missing_code");

  const flow = await env.DB.prepare(
    "SELECT verifier, nonce, expires_at FROM auth_flows WHERE state = ?",
  ).bind(state).first();
  await env.DB.prepare("DELETE FROM auth_flows WHERE state = ?").bind(state).run();
  if (!flow || Number(flow.expires_at) < Date.now()) {
    return redirectToApp(env, "auth_error", "expired_login");
  }

  const credentials = btoa(`${env.TELEGRAM_CLIENT_ID}:${env.TELEGRAM_CLIENT_SECRET}`);
  const tokenResponse = await fetch("https://oauth.telegram.org/token", {
    method: "POST",
    headers: {
      authorization: `Basic ${credentials}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl(request),
      client_id: String(env.TELEGRAM_CLIENT_ID),
      code_verifier: flow.verifier,
    }),
  });
  if (!tokenResponse.ok) {
    console.error("Telegram token exchange failed", tokenResponse.status);
    return redirectToApp(env, "auth_error", "token_exchange_failed");
  }

  try {
    const tokens = await tokenResponse.json();
    const claims = await verifyTelegramIdToken(tokens.id_token, env, flow.nonce);
    const userId = String(claims.sub);
    const telegramId = String(claims.id || claims.sub);
    const displayName = String(claims.name || claims.preferred_username || "Користувач Telegram");
    const now = Date.now();
    const userCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first();


    await env.DB.prepare(
      `INSERT INTO users (id, telegram_id, display_name, username, picture_url, created_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         telegram_id = excluded.telegram_id,
         display_name = excluded.display_name,
         username = excluded.username,
         picture_url = excluded.picture_url,
         last_login_at = excluded.last_login_at`,
    ).bind(
      userId,
      telegramId,
      displayName,
      claims.preferred_username ? String(claims.preferred_username) : null,
      claims.picture ? String(claims.picture) : null,
      now,
      now,
    ).run();

    if (Number(userCount?.count || 0) === 0) {
      await env.DB.prepare("UPDATE reminders SET user_id = ? WHERE user_id IS NULL").bind(userId).run();
    }

    const welcomeKey = `welcome:${userId}`;
    const welcomeSent = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(welcomeKey).first();
    if (!welcomeSent) {
      try {
        await sendTelegramWelcome(env, telegramId, displayName);
        await env.DB.prepare(
          "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ).bind(welcomeKey, String(now)).run();
      } catch (welcomeError) {
        console.error("Failed to send Telegram welcome", welcomeError);
      }
    }

    const loginCode = randomToken(32);
    await env.DB.prepare(
      "INSERT INTO login_codes (code_hash, user_id, expires_at) VALUES (?, ?, ?)",
    ).bind(await sha256(loginCode), userId, now + LOGIN_CODE_TTL).run();
    return redirectToApp(env, "login_code", loginCode);
  } catch (authError) {
    console.error("Telegram ID token validation failed", authError);
    return redirectToApp(env, "auth_error", "invalid_identity");
  }
}


function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualText(left, right) {
  const a = new TextEncoder().encode(String(left || ""));
  const b = new TextEncoder().encode(String(right || ""));
  if (a.length !== b.length) return false;

  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a[index] ^ b[index];
  }
  return difference === 0;
}

async function hmacSha256(keyBytes, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value),
  );

  return new Uint8Array(signature);
}

async function verifyTelegramWebAppData(initData, env) {
  if (!env.TELEGRAM_BOT_TOKEN) {
    throw new Error("Telegram bot token is not configured");
  }

  const params = new URLSearchParams(String(initData || ""));
  const receivedHash = params.get("hash") || "";
  const authDate = Number(params.get("auth_date") || 0);

  if (!receivedHash || !authDate) {
    throw new Error("Invalid Telegram Mini App data");
  }

  const now = Math.floor(Date.now() / 1000);
  if (authDate > now + 300 || now - authDate > 24 * 60 * 60) {
    throw new Error("Telegram Mini App data expired");
  }

  const dataCheckString = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = await hmacSha256(
    new TextEncoder().encode("WebAppData"),
    env.TELEGRAM_BOT_TOKEN,
  );

  const calculatedHash = bytesToHex(
    await hmacSha256(secretKey, dataCheckString),
  );

  if (!timingSafeEqualText(calculatedHash, receivedHash.toLowerCase())) {
    throw new Error("Invalid Telegram Mini App signature");
  }

  let telegramUser;
  try {
    telegramUser = JSON.parse(params.get("user") || "null");
  } catch {
    telegramUser = null;
  }

  if (!telegramUser?.id) {
    throw new Error("Telegram Mini App user is missing");
  }

  return telegramUser;
}

async function loginFromTelegramWebApp(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const initData = String(body.initData || "");

  if (!initData) {
    return json({ error: "Missing Telegram Mini App data" }, 400, origin);
  }

  try {
    const telegramUser = await verifyTelegramWebAppData(initData, env);
    const telegramId = String(telegramUser.id);
    const displayName = [
      telegramUser.first_name,
      telegramUser.last_name,
    ].filter(Boolean).join(" ").trim() || telegramUser.username || "Користувач Telegram";
    const now = Date.now();
    const userCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first();

    const existingByTelegram = await env.DB.prepare(
      `SELECT id, display_name, username, picture_url, telegram_id
       FROM users WHERE telegram_id = ?`,
    ).bind(telegramId).first();

    const userId = existingByTelegram?.id
      ? String(existingByTelegram.id)
      : telegramId;

    if (existingByTelegram) {
      await env.DB.prepare(
        `UPDATE users SET
           display_name = ?,
           username = ?,
           picture_url = ?,
           last_login_at = ?
         WHERE id = ?`,
      ).bind(
        displayName,
        telegramUser.username ? String(telegramUser.username) : null,
        telegramUser.photo_url ? String(telegramUser.photo_url) : null,
        now,
        userId,
      ).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users
           (id, telegram_id, display_name, username, picture_url, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        userId,
        telegramId,
        displayName,
        telegramUser.username ? String(telegramUser.username) : null,
        telegramUser.photo_url ? String(telegramUser.photo_url) : null,
        now,
        now,
      ).run();
    }

    if (Number(userCount?.count || 0) === 0) {
      await env.DB.prepare(
        "UPDATE reminders SET user_id = ? WHERE user_id IS NULL",
      ).bind(userId).run();
    }

    const row = await env.DB.prepare(
      `SELECT id, display_name, username, picture_url, telegram_id
       FROM users WHERE id = ?`,
    ).bind(userId).first();

    const sessionToken = randomToken(48);
    await env.DB.prepare(
      "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    ).bind(
      await sha256(sessionToken),
      userId,
      now,
      now + SESSION_TTL,
    ).run();

    return json({
      token: sessionToken,
      user: publicUser(row),
    }, 200, origin);
  } catch (error) {
    console.error("Telegram Mini App login failed", error);
    return json({
      error: "Не вдалося підтвердити вхід через Telegram Mini App",
      code: "INVALID_WEBAPP_DATA",
    }, 401, origin);
  }
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.display_name,
    username: row.username || "",
    picture: row.picture_url || "",
    telegramConnected: Boolean(row.telegram_id),
  };
}

async function exchangeLoginCode(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const code = String(body.code || "");
  if (!code) return json({ error: "Missing login code" }, 400, origin);

  const codeHash = await sha256(code);
  const row = await env.DB.prepare(
    `SELECT lc.user_id, lc.expires_at, u.id, u.display_name, u.username, u.picture_url, u.telegram_id
     FROM login_codes lc JOIN users u ON u.id = lc.user_id
     WHERE lc.code_hash = ?`,
  ).bind(codeHash).first();
  await env.DB.prepare("DELETE FROM login_codes WHERE code_hash = ?").bind(codeHash).run();
  if (!row || Number(row.expires_at) < Date.now()) {
    return json({ error: "Login code expired" }, 401, origin);
  }

  const sessionToken = randomToken(48);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
  ).bind(await sha256(sessionToken), row.user_id, now, now + SESSION_TTL).run();

  return json({ token: sessionToken, user: publicUser(row) }, 200, origin);
}

async function sessionUser(request, env) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const rawToken = header.slice(7).trim();
  if (!rawToken) return null;
  const tokenHash = await sha256(rawToken);
  const row = await env.DB.prepare(
    `SELECT s.token_hash, s.expires_at, u.id, u.display_name, u.username, u.picture_url, u.telegram_id
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`,
  ).bind(tokenHash).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  return { ...row, tokenHash };
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function normalizeTimeZone(value) {
  const fallback = "Europe/Kyiv";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value || fallback }).format();
    return value || fallback;
  } catch {
    return fallback;
  }
}

function zonedParts(timestamp, timeZone) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(timestamp));
  const values = Object.fromEntries(parts.filter((part) => part.type !== "literal").map((part) => [part.type, Number(part.value)]));
  return { year: values.year, month: values.month, day: values.day, hour: values.hour, minute: values.minute, second: values.second };
}

function localPartsToTimestamp(parts, timeZone) {
  const wanted = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second || 0);
  let guess = wanted;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const actual = zonedParts(guess, timeZone);
    const represented = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, actual.second || 0);
    guess += wanted - represented;
  }
  return guess;
}

function addLocalDays(parts, days) {
  const date = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days, parts.hour, parts.minute, parts.second || 0));
  return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate(), hour: parts.hour, minute: parts.minute, second: parts.second || 0 };
}

function advanceOccurrence(parts, type, interval) {
  if (type === "monthly") {
    const first = new Date(Date.UTC(parts.year, parts.month - 1 + interval, 1));
    const lastDay = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 0)).getUTCDate();
    return { ...parts, year: first.getUTCFullYear(), month: first.getUTCMonth() + 1, day: Math.min(parts.day, lastDay) };
  }
  if (type === "weekly") return addLocalDays(parts, interval * 7);
  if (type === "weekdays") {
    let next = parts;
    do {
      next = addLocalDays(next, 1);
    } while ([0, 6].includes(new Date(Date.UTC(next.year, next.month - 1, next.day)).getUTCDay()));
    return next;
  }
  return addLocalDays(parts, interval);
}

function nextOccurrence(reminder, now = Date.now()) {
  const type = reminder.recurrence_type || "none";
  if (type === "none") return null;
  const timeZone = normalizeTimeZone(reminder.timezone);
  const interval = Math.max(1, Math.min(52, Number(reminder.recurrence_interval) || 1));
  let parts = zonedParts(Number(reminder.due_at), timeZone);
  let next = Number(reminder.due_at);
  for (let step = 0; step < 500 && next <= now; step += 1) {
    parts = advanceOccurrence(parts, type, interval);
    next = localPartsToTimestamp(parts, timeZone);
  }
  return next > now ? next : null;
}

function recurrenceLabel(reminder) {
  const interval = Math.max(1, Number(reminder.recurrence_interval) || 1);
  const labels = {
    daily: interval === 1 ? "Щодня" : `Кожні ${interval} дні`,
    weekdays: "У робочі дні",
    weekly: interval === 1 ? "Щотижня" : `Кожні ${interval} тижні`,
    monthly: interval === 1 ? "Щомісяця" : `Кожні ${interval} місяці`,
  };
  return labels[reminder.recurrence_type] || "";
}

async function sendTelegram(env, reminder) {
  if (!reminder.telegram_id) throw new Error("Telegram account is not connected");
  const due = new Date(reminder.due_at);
  const timeZone = normalizeTimeZone(reminder.timezone);
  const date = new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone }).format(due);
  const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone }).format(due);
  const priorities = {
    high: { icon: "🔴", label: "Висока критичність" },
    medium: { icon: "🟡", label: "Середня критичність" },
    low: { icon: "🟢", label: "Низька критичність" },
  };
  const priority = priorities[reminder.priority] || priorities.medium;
  const isTask = reminder.item_type === "task";
  const repeat = recurrenceLabel(reminder);
  const text = [
    isTask ? "📋 <b>ТЕРМІН ЗАДАЧІ</b>" : "🔔 <b>НАГАДУВАННЯ</b>",
    "━━━━━━━━━━━━━━",
    "",
    `<b>${escapeHtml(reminder.title)}</b>`,
    ...(reminder.note ? [`📝 ${escapeHtml(reminder.note)}`] : []),
    "",
    `${priority.icon} <b>Критичність:</b> ${priority.label}`,
    `📅 <b>Дата:</b> ${date}`,
    `⏰ <b>Час:</b> ${time}`,
    ...(repeat ? [`🔁 <b>Повторення:</b> ${repeat}`] : []),
    ...(isTask ? [`📌 <b>Статус:</b> ${reminder.status === "in_progress" ? "У роботі" : "Заплановано"}`] : []),
    "",
    isTask ? "✨ <i>Час перейти до виконання задачі.</i>" : "✨ <i>Час перейти до запланованого.</i>",
  ].join("\n");

  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: reminder.telegram_id,
      text,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{ text: "✅ Виконано", callback_data: `done:${reminder.id}` }],
          [
            { text: "⏱ +10 хв", callback_data: `delay10:${reminder.id}` },
            { text: "🕐 +1 година", callback_data: `delay60:${reminder.id}` },
          ],
          [{ text: "📅 На завтра", callback_data: `tomorrow:${reminder.id}` }],
          [{ text: "🌿 Відкрити «Нагадай»", url: appUrl(env) }],
        ],
      },
    }),
  });
  if (!response.ok) throw new Error(`Telegram returned ${response.status}`);
}

async function sendTelegramWelcome(env, telegramId, displayName) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error("Telegram bot token is not configured");
  const text = [
    `👋 Вітаємо, <b>${escapeHtml(displayName)}</b>!`,
    "",
    "Бот «Нагадай» підключено до вашого облікового запису.",
    "Ваші нагадування приватні — інші користувачі їх не бачать.",
  ].join("\n");
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: telegramId,
      text,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "🌿 Відкрити «Нагадай»", url: appUrl(env) }]],
      },
    }),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Telegram welcome returned ${response.status}: ${details.slice(0, 300)}`);
  }
}

async function isBotConnected(env, userId) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?")
    .bind(`welcome:${userId}`).first();
  return Boolean(row?.value);
}

async function telegramApi(env, method, payload) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error("Telegram bot token is not configured");
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(`Telegram ${method} returned ${response.status}: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return data;
}

async function answerCallback(env, callbackQueryId, text, showAlert = false) {
  return telegramApi(env, "answerCallbackQuery", {
    callback_query_id: callbackQueryId,
    text,
    show_alert: showAlert,
  });
}

async function editTelegramMessage(env, chatId, messageId, text) {
  return telegramApi(env, "editMessageText", {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "🌿 Відкрити «Нагадай»", url: appUrl(env) }]],
    },
  });
}

async function handleTelegramStart(env, message) {
  const telegramId = String(message.chat?.id || "");
  if (!telegramId) return;
  const user = await env.DB.prepare(
    "SELECT id, telegram_id, display_name FROM users WHERE telegram_id = ?",
  ).bind(telegramId).first();
  if (!user) {
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "Спочатку увійдіть у «Нагадай» через Telegram на сайті.",
      reply_markup: { inline_keyboard: [[{ text: "🌿 Відкрити «Нагадай»", url: appUrl(env) }]] },
    });
    return;
  }
  await sendTelegramWelcome(env, telegramId, user.display_name);
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).bind(`welcome:${user.id}`, String(Date.now())).run();
}

async function handleReminderCallback(env, callbackQuery) {
  const callbackId = String(callbackQuery.id || "");
  const data = String(callbackQuery.data || "");
  const chatId = String(callbackQuery.message?.chat?.id || "");
  const messageId = callbackQuery.message?.message_id;
  const [action, reminderId] = data.split(":", 2);
  if (!callbackId || !chatId || !messageId || !reminderId) return;

  const reminder = await env.DB.prepare(
    `SELECT r.id, r.user_id, r.title, r.note, r.due_at, r.done, r.sent, r.status, r.timezone,
            u.telegram_id
     FROM reminders r JOIN users u ON u.id = r.user_id
     WHERE r.id = ? AND u.telegram_id = ?`,
  ).bind(reminderId, chatId).first();

  if (!reminder) {
    await answerCallback(env, callbackId, "Нагадування не знайдено", true);
    return;
  }

  const now = Date.now();
  let message = "";
  if (action === "done") {
    await env.DB.prepare(
      "UPDATE reminders SET done = 1, sent = 1, status = 'done', updated_at = ? WHERE id = ? AND user_id = ?",
    ).bind(now, reminder.id, reminder.user_id).run();
    message = `✅ <b>Виконано</b>

${escapeHtml(reminder.title)}`;
    await answerCallback(env, callbackId, "Позначено виконаним");
  } else if (action === "delay10" || action === "delay60") {
    const minutes = action === "delay10" ? 10 : 60;
    const nextDueAt = now + minutes * 60 * 1000;
    await env.DB.prepare(
      "UPDATE reminders SET due_at = ?, done = 0, sent = 0, status = 'planned', updated_at = ? WHERE id = ? AND user_id = ?",
    ).bind(nextDueAt, now, reminder.id, reminder.user_id).run();
    const timeZone = normalizeTimeZone(reminder.timezone);
    const nextTime = new Intl.DateTimeFormat("uk-UA", {
      hour: "2-digit", minute: "2-digit", timeZone,
    }).format(new Date(nextDueAt));
    message = `⏱ <b>Відкладено</b>

${escapeHtml(reminder.title)}

Нове нагадування о <b>${nextTime}</b>`;
    await answerCallback(env, callbackId, `Відкладено на ${minutes} хв`);
  } else if (action === "tomorrow") {
    const timeZone = normalizeTimeZone(reminder.timezone);
    const current = zonedParts(Number(reminder.due_at), timeZone);
    let nextDueAt = localPartsToTimestamp(addLocalDays(current, 1), timeZone);
    if (nextDueAt <= now) nextDueAt = localPartsToTimestamp(addLocalDays(zonedParts(now, timeZone), 1), timeZone);
    await env.DB.prepare(
      "UPDATE reminders SET due_at = ?, done = 0, sent = 0, status = 'planned', updated_at = ? WHERE id = ? AND user_id = ?",
    ).bind(nextDueAt, now, reminder.id, reminder.user_id).run();
    const date = new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone }).format(new Date(nextDueAt));
    const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone }).format(new Date(nextDueAt));
    message = `📅 <b>Перенесено</b>

${escapeHtml(reminder.title)}

Нова дата: <b>${date}, ${time}</b>`;
    await answerCallback(env, callbackId, "Перенесено на завтра");
  } else {
    await answerCallback(env, callbackId, "Невідома дія", true);
    return;
  }

  await editTelegramMessage(env, chatId, messageId, message);
}

async function handleTelegramWebhook(request, env) {
  if (env.TELEGRAM_WEBHOOK_SECRET) {
    const provided = request.headers.get("x-telegram-bot-api-secret-token") || "";
    if (provided !== env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response("Forbidden", { status: 403 });
    }
  }

  const update = await request.json().catch(() => null);
  if (!update) return new Response("Bad Request", { status: 400 });

  try {
    if (update.callback_query) {
      await handleReminderCallback(env, update.callback_query);
    } else if (update.message && /^\/start(?:@\w+)?(?:\s|$)/i.test(String(update.message.text || ""))) {
      await handleTelegramStart(env, update.message);
    }
  } catch (error) {
    console.error("Telegram webhook processing failed", error);
  }

  return new Response("OK", { status: 200 });
}

async function processTelegramUpdates(env) {
  if (!env.TELEGRAM_BOT_TOKEN) return;
  const saved = await env.DB.prepare("SELECT value FROM settings WHERE key = ?")
    .bind("telegram_update_offset").first();
  let nextOffset = Number(saved?.value || 0);
  const params = new URLSearchParams({
    offset: String(nextOffset),
    limit: "100",
    timeout: "0",
    allowed_updates: JSON.stringify(["message"]),
  });
  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates?${params}`,
  );
  if (!response.ok) throw new Error(`Telegram getUpdates returned ${response.status}`);
  const payload = await response.json();
  for (const update of payload.result || []) {
    nextOffset = Math.max(nextOffset, Number(update.update_id) + 1);
    const message = update.message;
    if (!message || !/^\/start(?:@\w+)?(?:\s|$)/i.test(String(message.text || ""))) continue;
    const telegramId = String(message.chat?.id || "");
    if (!telegramId) continue;
    const user = await env.DB.prepare(
      "SELECT id, telegram_id, display_name FROM users WHERE telegram_id = ?",
    ).bind(telegramId).first();
    if (!user || await isBotConnected(env, user.id)) continue;
    try {
      await sendTelegramWelcome(env, telegramId, user.display_name);
      await env.DB.prepare(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      ).bind(`welcome:${user.id}`, String(Date.now())).run();
    } catch (error) {
      console.error("Failed to activate bot after Start", error);
    }
  }
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).bind("telegram_update_offset", String(nextOffset)).run();
}

async function connectBot(env, user, origin) {
  try {
    await sendTelegramWelcome(env, user.telegram_id, user.display_name);
    await env.DB.prepare(
      "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    ).bind(`welcome:${user.id}`, String(Date.now())).run();
    return json({ ok: true, connected: true }, 200, origin);
  } catch (error) {
    return json({
      error: "Відкрийте бота, натисніть Start і повторіть перевірку",
      code: "BOT_NOT_STARTED",
    }, 409, origin);
  }
}

async function listReminders(env, userId, origin) {
  const { results } = await env.DB.prepare(
    `SELECT id, title, note, due_at, priority, done, sent, item_type, status,
            recurrence_type, recurrence_interval, timezone, created_at, updated_at
     FROM reminders WHERE user_id = ? ORDER BY due_at`,
  ).bind(userId).all();
  return json({ reminders: results || [] }, 200, origin);
}

async function upsertReminder(request, env, userId, origin) {
  const body = await request.json().catch(() => ({}));
  const id = String(body.id || "");
  const title = String(body.title || "").trim();
  const note = String(body.note || "");
  const dueAt = Date.parse(body.dueAt);
  const priority = ["high", "medium", "low"].includes(body.priority) ? body.priority : "medium";
  const itemType = body.itemType === "task" ? "task" : "reminder";
  const allowedStatuses = ["planned", "in_progress", "done"];
  let status = allowedStatuses.includes(body.status) ? body.status : "planned";
  if (body.done) status = "done";
  const done = status === "done" ? 1 : 0;
  const allowedRecurrences = ["none", "daily", "weekdays", "weekly", "monthly"];
  const recurrenceType = itemType === "reminder" && allowedRecurrences.includes(body.recurrenceType) ? body.recurrenceType : "none";
  const recurrenceInterval = Math.max(1, Math.min(52, Number(body.recurrenceInterval) || 1));
  const timezone = normalizeTimeZone(String(body.timezone || "Europe/Kyiv"));
  if (!id || !title || !Number.isFinite(dueAt)) {
    return json({ error: "Invalid reminder" }, 400, origin);
  }

  const existing = await env.DB.prepare("SELECT user_id FROM reminders WHERE id = ?").bind(id).first();
  if (existing && existing.user_id !== userId) {
    return json({ error: "Reminder ID conflict" }, 409, origin);
  }

  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO reminders
       (id, user_id, title, note, due_at, priority, done, sent, item_type, status,
        recurrence_type, recurrence_interval, timezone, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       title = excluded.title,
       note = excluded.note,
       due_at = excluded.due_at,
       priority = excluded.priority,
       done = excluded.done,
       sent = excluded.sent,
       item_type = excluded.item_type,
       status = excluded.status,
       recurrence_type = excluded.recurrence_type,
       recurrence_interval = excluded.recurrence_interval,
       timezone = excluded.timezone,
       updated_at = excluded.updated_at`,
  ).bind(
    id, userId, title, note, dueAt, priority, done, done ? 1 : 0, itemType, status,
    recurrenceType, recurrenceInterval, timezone, now, now,
  ).run();
  return json({ ok: true, id }, existing ? 200 : 201, origin);
}

async function processDueReminders(env) {
  const now = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.user_id, r.title, r.note, r.due_at, r.priority, r.item_type, r.status,
            r.recurrence_type, r.recurrence_interval, r.timezone, u.telegram_id
     FROM reminders r JOIN users u ON u.id = r.user_id
     WHERE r.sent = 0 AND r.done = 0 AND r.due_at <= ?
     ORDER BY r.due_at LIMIT 50`,
  ).bind(now).all();

  for (const reminder of results || []) {
    try {
      await sendTelegram(env, reminder);
      const nextDueAt = reminder.item_type === "reminder" ? nextOccurrence(reminder, Date.now()) : null;
      if (nextDueAt) {
        await env.DB.prepare(
          "UPDATE reminders SET due_at = ?, sent = 0, updated_at = ? WHERE id = ? AND user_id = ?",
        ).bind(nextDueAt, Date.now(), reminder.id, reminder.user_id).run();
      } else {
        await env.DB.prepare(
          "UPDATE reminders SET sent = 1, updated_at = ? WHERE id = ? AND user_id = ?",
        ).bind(Date.now(), reminder.id, reminder.user_id).run();
      }
    } catch (error) {
      console.error("Failed to send reminder", reminder.id, error);
    }
  }
}

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/api/health") {
    return json({ ok: true, service: "nahadai-telegram", accounts: true });
  }
  if (url.pathname === "/api/auth/login" && request.method === "GET") {
    return startLogin(request, env);
  }
  if (url.pathname === "/api/auth/telegram/callback" && request.method === "GET") {
    return finishLogin(request, env);
  }
  if (url.pathname === "/api/telegram/webhook" && request.method === "POST") {
    return handleTelegramWebhook(request, env);
  }

  const origin = originFor(request, env);
  if (request.method === "OPTIONS") {
    return origin
      ? new Response(null, { status: 204, headers: corsHeaders(origin) })
      : json({ error: "Origin not allowed" }, 403);
  }
  if (!origin) return json({ error: "Origin not allowed" }, 403);

  if (url.pathname === "/api/auth/exchange" && request.method === "POST") {
    return exchangeLoginCode(request, env, origin);
  }

  if (url.pathname === "/api/auth/webapp" && request.method === "POST") {
    return loginFromTelegramWebApp(request, env, origin);
  }

  const user = await sessionUser(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, origin);

  if (url.pathname === "/api/me" && request.method === "GET") {
    return json({ user: publicUser(user) }, 200, origin);
  }
  if (url.pathname === "/api/logout" && request.method === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(user.tokenHash).run();
    return json({ ok: true }, 200, origin);
  }
  if (url.pathname === "/api/bot/status" && request.method === "GET") {
    return json({ connected: await isBotConnected(env, user.id) }, 200, origin);
  }
  if (url.pathname === "/api/bot/connect" && request.method === "POST") {
    return connectBot(env, user, origin);
  }
  if (url.pathname === "/api/reminders" && request.method === "GET") {
    return listReminders(env, user.id, origin);
  }
  if (url.pathname === "/api/reminders" && request.method === "POST") {
    return upsertReminder(request, env, user.id, origin);
  }
  if (url.pathname.startsWith("/api/reminders/") && request.method === "DELETE") {
    const id = decodeURIComponent(url.pathname.split("/").pop());
    await env.DB.prepare("DELETE FROM reminders WHERE id = ? AND user_id = ?").bind(id, user.id).run();
    return json({ ok: true }, 200, origin);
  }

  return json({ error: "Not found" }, 404, origin);
}

export default {
  fetch: handleRequest,
  scheduled(_event, env, ctx) {
    ctx.waitUntil(processDueReminders(env));
  },
};




