var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// index.js
var jwksCache;
var jwksCachedAt = 0;
var SESSION_TTL = 365 * 24 * 60 * 60 * 1e3;
var FLOW_TTL = 10 * 60 * 1e3;
var LOGIN_CODE_TTL = 5 * 60 * 1e3;
function corsHeaders(origin) {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "cache-control": "no-store",
    vary: "Origin"
  };
}
__name(corsHeaders, "corsHeaders");
function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders(origin),
      "content-type": "application/json; charset=utf-8"
    }
  });
}
__name(json, "json");
function originFor(request, env) {
  const origin = request.headers.get("origin") || "";
  if (!env.ALLOWED_ORIGIN || env.ALLOWED_ORIGIN === "*") return "*";
  return origin === env.ALLOWED_ORIGIN ? origin : "";
}
__name(originFor, "originFor");
function appUrl(env) {
  return env.APP_URL || "https://viacheslavmyazin.github.io/nahadai-reminder/";
}
__name(appUrl, "appUrl");
function callbackUrl(request) {
  return new URL("/api/auth/telegram/callback", request.url).toString();
}
__name(callbackUrl, "callbackUrl");
function randomToken(bytes = 32) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return bytesToBase64Url(value);
}
__name(randomToken, "randomToken");
function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(bytesToBase64Url, "bytesToBase64Url");
function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
__name(base64UrlToBytes, "base64UrlToBytes");
function decodeJwtPart(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value)));
}
__name(decodeJwtPart, "decodeJwtPart");
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}
__name(sha256, "sha256");
async function telegramKeys() {
  if (jwksCache && Date.now() - jwksCachedAt < 60 * 60 * 1e3) return jwksCache;
  const response = await fetch("https://oauth.telegram.org/.well-known/jwks.json");
  if (!response.ok) throw new Error("Telegram JWKS unavailable");
  jwksCache = await response.json();
  jwksCachedAt = Date.now();
  return jwksCache;
}
__name(telegramKeys, "telegramKeys");
async function verifyTelegramIdToken(token, env, expectedNonce) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid ID token");
  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  if (header.alg !== "RS256" || !header.kid) throw new Error("Unsupported ID token");
  const jwks = await telegramKeys();
  const jwk = jwks.keys?.find((key2) => key2.kid === header.kid);
  if (!jwk) throw new Error("Signing key not found");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!verified) throw new Error("Invalid ID token signature");
  const now = Math.floor(Date.now() / 1e3);
  const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== "https://oauth.telegram.org") throw new Error("Invalid issuer");
  if (!audience.map(String).includes(String(env.TELEGRAM_CLIENT_ID))) throw new Error("Invalid audience");
  if (!payload.exp || payload.exp <= now) throw new Error("Expired ID token");
  if (payload.iat && payload.iat > now + 300) throw new Error("Invalid issued-at time");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("Invalid nonce");
  return payload;
}
__name(verifyTelegramIdToken, "verifyTelegramIdToken");
function redirectToApp(env, key, value) {
  const target = new URL(appUrl(env));
  if (key && value) target.searchParams.set(key, value);
  return Response.redirect(target.toString(), 302);
}
__name(redirectToApp, "redirectToApp");
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
    "INSERT INTO auth_flows (state, verifier, nonce, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(state, verifier, nonce, expiresAt).run();
  const params = new URLSearchParams({
    client_id: String(env.TELEGRAM_CLIENT_ID),
    redirect_uri: callbackUrl(request),
    response_type: "code",
    scope: "openid profile telegram:bot_access",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  return Response.redirect(`https://oauth.telegram.org/auth?${params}`, 302);
}
__name(startLogin, "startLogin");
async function finishLogin(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  if (error) return redirectToApp(env, "auth_error", error);
  if (!code || !state) return redirectToApp(env, "auth_error", "missing_code");
  const flow = await env.DB.prepare(
    "SELECT verifier, nonce, expires_at FROM auth_flows WHERE state = ?"
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
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl(request),
      client_id: String(env.TELEGRAM_CLIENT_ID),
      code_verifier: flow.verifier
    })
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
    const displayName = String(claims.name || claims.preferred_username || "\u041A\u043E\u0440\u0438\u0441\u0442\u0443\u0432\u0430\u0447 Telegram");
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
         last_login_at = excluded.last_login_at`
    ).bind(
      userId,
      telegramId,
      displayName,
      claims.preferred_username ? String(claims.preferred_username) : null,
      claims.picture ? String(claims.picture) : null,
      now,
      now
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
          "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        ).bind(welcomeKey, String(now)).run();
      } catch (welcomeError) {
        console.error("Failed to send Telegram welcome", welcomeError);
      }
    }
    const loginCode = randomToken(32);
    await env.DB.prepare(
      "INSERT INTO login_codes (code_hash, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(await sha256(loginCode), userId, now + LOGIN_CODE_TTL).run();
    return redirectToApp(env, "login_code", loginCode);
  } catch (authError) {
    console.error("Telegram ID token validation failed", authError);
    return redirectToApp(env, "auth_error", "invalid_identity");
  }
}
__name(finishLogin, "finishLogin");
function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
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
__name(timingSafeEqualText, "timingSafeEqualText");
async function hmacSha256(keyBytes, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );
  return new Uint8Array(signature);
}
__name(hmacSha256, "hmacSha256");
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
  const now = Math.floor(Date.now() / 1e3);
  if (authDate > now + 300 || now - authDate > 24 * 60 * 60) {
    throw new Error("Telegram Mini App data expired");
  }
  const dataCheckString = [...params.entries()].filter(([key]) => key !== "hash").sort(([left], [right]) => left.localeCompare(right)).map(([key, value]) => `${key}=${value}`).join("\n");
  const secretKey = await hmacSha256(
    new TextEncoder().encode("WebAppData"),
    env.TELEGRAM_BOT_TOKEN
  );
  const calculatedHash = bytesToHex(
    await hmacSha256(secretKey, dataCheckString)
  );
  if (!timingSafeEqualText(calculatedHash, receivedHash.toLowerCase())) {
    throw new Error("Invalid Telegram Mini App signature");
  }
  let telegramUser2;
  try {
    telegramUser2 = JSON.parse(params.get("user") || "null");
  } catch {
    telegramUser2 = null;
  }
  if (!telegramUser2?.id) {
    throw new Error("Telegram Mini App user is missing");
  }
  return telegramUser2;
}
__name(verifyTelegramWebAppData, "verifyTelegramWebAppData");
async function loginFromTelegramWebApp(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const initData = String(body.initData || "");
  if (!initData) {
    return json({ error: "Missing Telegram Mini App data" }, 400, origin);
  }
  try {
    const telegramUser2 = await verifyTelegramWebAppData(initData, env);
    const telegramId = String(telegramUser2.id);
    const displayName = [
      telegramUser2.first_name,
      telegramUser2.last_name
    ].filter(Boolean).join(" ").trim() || telegramUser2.username || "\u041A\u043E\u0440\u0438\u0441\u0442\u0443\u0432\u0430\u0447 Telegram";
    const now = Date.now();
    const userCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first();
    const existingByTelegram = await env.DB.prepare(
      `SELECT id, display_name, username, picture_url, telegram_id
       FROM users WHERE telegram_id = ?`
    ).bind(telegramId).first();
    const userId = existingByTelegram?.id ? String(existingByTelegram.id) : telegramId;
    if (existingByTelegram) {
      await env.DB.prepare(
        `UPDATE users SET
           display_name = ?,
           username = ?,
           picture_url = ?,
           last_login_at = ?
         WHERE id = ?`
      ).bind(
        displayName,
        telegramUser2.username ? String(telegramUser2.username) : null,
        telegramUser2.photo_url ? String(telegramUser2.photo_url) : null,
        now,
        userId
      ).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users
           (id, telegram_id, display_name, username, picture_url, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        userId,
        telegramId,
        displayName,
        telegramUser2.username ? String(telegramUser2.username) : null,
        telegramUser2.photo_url ? String(telegramUser2.photo_url) : null,
        now,
        now
      ).run();
    }
    if (Number(userCount?.count || 0) === 0) {
      await env.DB.prepare(
        "UPDATE reminders SET user_id = ? WHERE user_id IS NULL"
      ).bind(userId).run();
    }
    const row = await env.DB.prepare(
      `SELECT id, display_name, username, picture_url, telegram_id
       FROM users WHERE id = ?`
    ).bind(userId).first();
    const sessionToken = randomToken(48);
    await env.DB.prepare(
      "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
    ).bind(
      await sha256(sessionToken),
      userId,
      now,
      now + SESSION_TTL
    ).run();
    return json({
      token: sessionToken,
      user: publicUser(row)
    }, 200, origin);
  } catch (error) {
    console.error("Telegram Mini App login failed", error);
    return json({
      error: "\u041D\u0435 \u0432\u0434\u0430\u043B\u043E\u0441\u044F \u043F\u0456\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0438 \u0432\u0445\u0456\u0434 \u0447\u0435\u0440\u0435\u0437 Telegram Mini App",
      code: "INVALID_WEBAPP_DATA"
    }, 401, origin);
  }
}
__name(loginFromTelegramWebApp, "loginFromTelegramWebApp");
function publicUser(row) {
  return {
    id: row.id,
    name: row.display_name,
    username: row.username || "",
    picture: row.picture_url || "",
    telegramConnected: Boolean(row.telegram_id)
  };
}
__name(publicUser, "publicUser");
async function exchangeLoginCode(request, env, origin) {
  const body = await request.json().catch(() => ({}));
  const code = String(body.code || "");
  if (!code) return json({ error: "Missing login code" }, 400, origin);
  const codeHash = await sha256(code);
  const row = await env.DB.prepare(
    `SELECT lc.user_id, lc.expires_at, u.id, u.display_name, u.username, u.picture_url, u.telegram_id
     FROM login_codes lc JOIN users u ON u.id = lc.user_id
     WHERE lc.code_hash = ?`
  ).bind(codeHash).first();
  await env.DB.prepare("DELETE FROM login_codes WHERE code_hash = ?").bind(codeHash).run();
  if (!row || Number(row.expires_at) < Date.now()) {
    return json({ error: "Login code expired" }, 401, origin);
  }
  const sessionToken = randomToken(48);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(await sha256(sessionToken), row.user_id, now, now + SESSION_TTL).run();
  return json({ token: sessionToken, user: publicUser(row) }, 200, origin);
}
__name(exchangeLoginCode, "exchangeLoginCode");
async function sessionUser(request, env) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const rawToken = header.slice(7).trim();
  if (!rawToken) return null;
  const tokenHash = await sha256(rawToken);
  const row = await env.DB.prepare(
    `SELECT s.token_hash, s.expires_at, u.id, u.display_name, u.username, u.picture_url, u.telegram_id
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`
  ).bind(tokenHash).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  return { ...row, tokenHash };
}
__name(sessionUser, "sessionUser");
function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}
__name(escapeHtml, "escapeHtml");
function normalizeTimeZone(value) {
  const fallback = "Europe/Kyiv";
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value || fallback }).format();
    return value || fallback;
  } catch {
    return fallback;
  }
}
__name(normalizeTimeZone, "normalizeTimeZone");
function zonedParts(timestamp, timeZone) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23"
  }).formatToParts(new Date(timestamp));
  const values = Object.fromEntries(parts.filter((part) => part.type !== "literal").map((part) => [part.type, Number(part.value)]));
  return { year: values.year, month: values.month, day: values.day, hour: values.hour, minute: values.minute, second: values.second };
}
__name(zonedParts, "zonedParts");
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
__name(localPartsToTimestamp, "localPartsToTimestamp");
function addLocalDays(parts, days) {
  const date = new Date(Date.UTC(parts.year, parts.month - 1, parts.day + days, parts.hour, parts.minute, parts.second || 0));
  return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate(), hour: parts.hour, minute: parts.minute, second: parts.second || 0 };
}
__name(addLocalDays, "addLocalDays");
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
__name(advanceOccurrence, "advanceOccurrence");
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
__name(nextOccurrence, "nextOccurrence");
function recurrenceLabel(reminder) {
  const interval = Math.max(1, Number(reminder.recurrence_interval) || 1);
  const labels = {
    daily: interval === 1 ? "\u0429\u043E\u0434\u043D\u044F" : `\u041A\u043E\u0436\u043D\u0456 ${interval} \u0434\u043D\u0456`,
    weekdays: "\u0423 \u0440\u043E\u0431\u043E\u0447\u0456 \u0434\u043D\u0456",
    weekly: interval === 1 ? "\u0429\u043E\u0442\u0438\u0436\u043D\u044F" : `\u041A\u043E\u0436\u043D\u0456 ${interval} \u0442\u0438\u0436\u043D\u0456`,
    monthly: interval === 1 ? "\u0429\u043E\u043C\u0456\u0441\u044F\u0446\u044F" : `\u041A\u043E\u0436\u043D\u0456 ${interval} \u043C\u0456\u0441\u044F\u0446\u0456`
  };
  return labels[reminder.recurrence_type] || "";
}
__name(recurrenceLabel, "recurrenceLabel");
async function sendTelegram(env, reminder) {
  if (!reminder.telegram_id) throw new Error("Telegram account is not connected");
  const due = new Date(reminder.due_at);
  const timeZone = normalizeTimeZone(reminder.timezone);
  const date = new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone }).format(due);
  const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone }).format(due);
  const priorities = {
    high: { icon: "\u{1F534}", label: "\u0412\u0438\u0441\u043E\u043A\u0430 \u043A\u0440\u0438\u0442\u0438\u0447\u043D\u0456\u0441\u0442\u044C" },
    medium: { icon: "\u{1F7E1}", label: "\u0421\u0435\u0440\u0435\u0434\u043D\u044F \u043A\u0440\u0438\u0442\u0438\u0447\u043D\u0456\u0441\u0442\u044C" },
    low: { icon: "\u{1F7E2}", label: "\u041D\u0438\u0437\u044C\u043A\u0430 \u043A\u0440\u0438\u0442\u0438\u0447\u043D\u0456\u0441\u0442\u044C" }
  };
  const priority = priorities[reminder.priority] || priorities.medium;
  const isTask = reminder.item_type === "task";
  const repeat = recurrenceLabel(reminder);
  const text = [
    isTask ? "\u{1F4CB} <b>\u0422\u0415\u0420\u041C\u0406\u041D \u0417\u0410\u0414\u0410\u0427\u0406</b>" : "\u{1F514} <b>\u041D\u0410\u0413\u0410\u0414\u0423\u0412\u0410\u041D\u041D\u042F</b>",
    "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501",
    "",
    `<b>${escapeHtml(reminder.title)}</b>`,
    ...reminder.note ? [`\u{1F4DD} ${escapeHtml(reminder.note)}`] : [],
    "",
    `${priority.icon} <b>\u041A\u0440\u0438\u0442\u0438\u0447\u043D\u0456\u0441\u0442\u044C:</b> ${priority.label}`,
    `\u{1F4C5} <b>\u0414\u0430\u0442\u0430:</b> ${date}`,
    `\u23F0 <b>\u0427\u0430\u0441:</b> ${time}`,
    ...repeat ? [`\u{1F501} <b>\u041F\u043E\u0432\u0442\u043E\u0440\u0435\u043D\u043D\u044F:</b> ${repeat}`] : [],
    ...isTask ? [`\u{1F4CC} <b>\u0421\u0442\u0430\u0442\u0443\u0441:</b> ${reminder.status === "in_progress" ? "\u0423 \u0440\u043E\u0431\u043E\u0442\u0456" : "\u0417\u0430\u043F\u043B\u0430\u043D\u043E\u0432\u0430\u043D\u043E"}`] : [],
    "",
    isTask ? "\u2728 <i>\u0427\u0430\u0441 \u043F\u0435\u0440\u0435\u0439\u0442\u0438 \u0434\u043E \u0432\u0438\u043A\u043E\u043D\u0430\u043D\u043D\u044F \u0437\u0430\u0434\u0430\u0447\u0456.</i>" : "\u2728 <i>\u0427\u0430\u0441 \u043F\u0435\u0440\u0435\u0439\u0442\u0438 \u0434\u043E \u0437\u0430\u043F\u043B\u0430\u043D\u043E\u0432\u0430\u043D\u043E\u0433\u043E.</i>"
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
          [{ text: "\u2705 \u0412\u0438\u043A\u043E\u043D\u0430\u043D\u043E", callback_data: `done:${reminder.id}` }],
          [
            { text: "\u23F1 +10 \u0445\u0432", callback_data: `delay10:${reminder.id}` },
            { text: "\u{1F550} +1 \u0433\u043E\u0434\u0438\u043D\u0430", callback_data: `delay60:${reminder.id}` }
          ],
          [{ text: "\u{1F4C5} \u041D\u0430 \u0437\u0430\u0432\u0442\u0440\u0430", callback_data: `tomorrow:${reminder.id}` }],
          [{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB", url: appUrl(env) }]
        ]
      }
    })
  });
  if (!response.ok) throw new Error(`Telegram returned ${response.status}`);
}
__name(sendTelegram, "sendTelegram");
async function sendTelegramWelcome(env, telegramId, displayName) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error("Telegram bot token is not configured");
  const text = [
    `\u{1F44B} \u0412\u0456\u0442\u0430\u0454\u043C\u043E, <b>${escapeHtml(displayName)}</b>!`,
    "",
    "\u0411\u043E\u0442 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB \u043F\u0456\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u043E \u0434\u043E \u0432\u0430\u0448\u043E\u0433\u043E \u043E\u0431\u043B\u0456\u043A\u043E\u0432\u043E\u0433\u043E \u0437\u0430\u043F\u0438\u0441\u0443.",
    "\u0412\u0430\u0448\u0456 \u043D\u0430\u0433\u0430\u0434\u0443\u0432\u0430\u043D\u043D\u044F \u043F\u0440\u0438\u0432\u0430\u0442\u043D\u0456 \u2014 \u0456\u043D\u0448\u0456 \u043A\u043E\u0440\u0438\u0441\u0442\u0443\u0432\u0430\u0447\u0456 \u0457\u0445 \u043D\u0435 \u0431\u0430\u0447\u0430\u0442\u044C."
  ].join("\n");
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: telegramId,
      text,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB", url: appUrl(env) }]]
      }
    })
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Telegram welcome returned ${response.status}: ${details.slice(0, 300)}`);
  }
}
__name(sendTelegramWelcome, "sendTelegramWelcome");
async function isBotConnected(env, userId) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(`welcome:${userId}`).first();
  return Boolean(row?.value);
}
__name(isBotConnected, "isBotConnected");
async function telegramApi(env, method, payload) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error("Telegram bot token is not configured");
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(`Telegram ${method} returned ${response.status}: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return data;
}
__name(telegramApi, "telegramApi");
async function answerCallback(env, callbackQueryId, text, showAlert = false) {
  return telegramApi(env, "answerCallbackQuery", {
    callback_query_id: callbackQueryId,
    text,
    show_alert: showAlert
  });
}
__name(answerCallback, "answerCallback");
async function editTelegramMessage(env, chatId, messageId, text) {
  return telegramApi(env, "editMessageText", {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB", url: appUrl(env) }]]
    }
  });
}
__name(editTelegramMessage, "editTelegramMessage");
function telegramMainKeyboard(env) {
  return {
    keyboard: [
      [{ text: "\u{1F4C5} \u0421\u044C\u043E\u0433\u043E\u0434\u043D\u0456" }, { text: "\u{1F4CB} \u0410\u043A\u0442\u0438\u0432\u043D\u0456" }],
      [{ text: "\u26A0\uFE0F \u041F\u0440\u043E\u0441\u0442\u0440\u043E\u0447\u0435\u043D\u0456" }, { text: "\u2795 \u041D\u043E\u0432\u0430 \u0437\u0430\u0434\u0430\u0447\u0430" }],
      [{ text: "\u{1F4CA} \u0421\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043A\u0430" }, { text: "\u{1F4C2} \u041F\u0440\u043E\u0454\u043A\u0442\u0438" }],
      [{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \u043F\u043B\u0430\u043D\u0443\u0432\u0430\u043B\u044C\u043D\u0438\u043A", web_app: { url: appUrl(env) } }]
    ],
    resize_keyboard: true,
    is_persistent: true,
    input_field_placeholder: "\u041E\u0431\u0435\u0440\u0456\u0442\u044C \u0434\u0456\u044E"
  };
}
__name(telegramMainKeyboard, "telegramMainKeyboard");
async function telegramUser(env, telegramId) {
  return env.DB.prepare(
    "SELECT id, telegram_id, display_name FROM users WHERE telegram_id = ?"
  ).bind(String(telegramId)).first();
}
__name(telegramUser, "telegramUser");
async function setTelegramState(env, telegramId, state) {
  const key = `telegram_state:${telegramId}`;
  if (!state) {
    await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
    return;
  }
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).bind(key, JSON.stringify(state)).run();
}
__name(setTelegramState, "setTelegramState");
async function getTelegramState(env, telegramId) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(`telegram_state:${telegramId}`).first();
  if (!row?.value) return null;
  try {
    return JSON.parse(row.value);
  } catch {
    return null;
  }
}
__name(getTelegramState, "getTelegramState");
function telegramDayBounds(now = Date.now(), timeZone = "Europe/Kyiv") {
  const local = zonedParts(now, timeZone);
  const start = localPartsToTimestamp({ ...local, hour: 0, minute: 0, second: 0 }, timeZone);
  const end = localPartsToTimestamp(addLocalDays({ ...local, hour: 0, minute: 0, second: 0 }, 1), timeZone);
  return { start, end };
}
__name(telegramDayBounds, "telegramDayBounds");
function priorityIcon(value) {
  return value === "high" ? "\u{1F534}" : value === "low" ? "\u{1F7E2}" : "\u{1F7E1}";
}
__name(priorityIcon, "priorityIcon");
async function sendTelegramMenu(env, telegramId, name = "") {
  const greeting = name ? `, <b>${escapeHtml(name)}</b>` : "";
  await telegramApi(env, "sendMessage", {
    chat_id: telegramId,
    text: `\u{1F33F} <b>\u041D\u0430\u0433\u0430\u0434\u0430\u0439</b>${greeting}

\u0429\u043E \u0431\u0430\u0436\u0430\u0454\u0442\u0435 \u0437\u0440\u043E\u0431\u0438\u0442\u0438?`,
    parse_mode: "HTML",
    reply_markup: telegramMainKeyboard(env)
  });
}
__name(sendTelegramMenu, "sendTelegramMenu");
async function sendTelegramList(env, telegramId, mode) {
  const user = await telegramUser(env, telegramId);
  if (!user) {
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "\u0421\u043F\u043E\u0447\u0430\u0442\u043A\u0443 \u0432\u0456\u0434\u043A\u0440\u0438\u0439\u0442\u0435 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB \u0456 \u0432\u0438\u043A\u043E\u043D\u0430\u0439\u0442\u0435 \u0432\u0445\u0456\u0434 \u0447\u0435\u0440\u0435\u0437 Telegram.",
      reply_markup: telegramMainKeyboard(env)
    });
    return;
  }
  const now = Date.now();
  const { start, end } = telegramDayBounds(now);
  let title = "\u{1F4CB} <b>\u0410\u043A\u0442\u0438\u0432\u043D\u0456 \u0437\u0430\u0434\u0430\u0447\u0456</b>";
  let query = "SELECT id, title, due_at, priority, item_type, done FROM reminders WHERE user_id = ? AND done = 0 ORDER BY due_at LIMIT 30";
  let params = [user.id];
  if (mode === "today") {
    title = "\u{1F4C5} <b>\u0421\u043F\u0440\u0430\u0432\u0438 \u043D\u0430 \u0441\u044C\u043E\u0433\u043E\u0434\u043D\u0456</b>";
    query = "SELECT id, title, due_at, priority, item_type, done FROM reminders WHERE user_id = ? AND due_at >= ? AND due_at < ? ORDER BY done, due_at LIMIT 30";
    params = [user.id, start, end];
  } else if (mode === "overdue") {
    title = "\u26A0\uFE0F <b>\u041F\u0440\u043E\u0441\u0442\u0440\u043E\u0447\u0435\u043D\u0456</b>";
    query = "SELECT id, title, due_at, priority, item_type, done FROM reminders WHERE user_id = ? AND done = 0 AND due_at < ? ORDER BY due_at LIMIT 30";
    params = [user.id, now];
  }
  const { results } = await env.DB.prepare(query).bind(...params).all();
  const rows = results || [];
  if (!rows.length) {
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: `${title}

\u0421\u043F\u0438\u0441\u043E\u043A \u043F\u043E\u0440\u043E\u0436\u043D\u0456\u0439 \u{1F389}`,
      parse_mode: "HTML",
      reply_markup: telegramMainKeyboard(env)
    });
    return;
  }
  const lines = [title, ""];
  for (const [index, item] of rows.entries()) {
    const due = new Date(Number(item.due_at));
    const date = new Intl.DateTimeFormat("uk-UA", { day: "2-digit", month: "2-digit", timeZone: "Europe/Kyiv" }).format(due);
    const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Kyiv" }).format(due);
    lines.push(`${index + 1}. ${priorityIcon(item.priority)} ${item.item_type === "task" ? "\u{1F4CB}" : "\u{1F514}"} <b>${escapeHtml(item.title)}</b>`);
    lines.push(`   \u{1F552} ${date}, ${time}`);
    lines.push("");
  }
  const keyboard = rows.filter((item) => !item.done).slice(0, 8).map((item) => [
    { text: `\u2705 ${String(item.title).slice(0, 22)}`, callback_data: `done:${item.id}` },
    { text: "\u{1F4C5} \u0417\u0430\u0432\u0442\u0440\u0430", callback_data: `tomorrow:${item.id}` }
  ]);
  keyboard.push([{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB", web_app: { url: appUrl(env) } }]);
  await telegramApi(env, "sendMessage", {
    chat_id: telegramId,
    text: lines.join("\n").slice(0, 3900),
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: keyboard }
  });
}
__name(sendTelegramList, "sendTelegramList");
async function sendTelegramStats(env, telegramId) {
  const user = await telegramUser(env, telegramId);
  if (!user) return sendTelegramMenu(env, telegramId);
  const now = Date.now();
  const { start, end } = telegramDayBounds(now);
  const row = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN done = 0 THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN done = 1 THEN 1 ELSE 0 END) AS done,
      SUM(CASE WHEN done = 0 AND due_at < ? THEN 1 ELSE 0 END) AS overdue,
      SUM(CASE WHEN due_at >= ? AND due_at < ? THEN 1 ELSE 0 END) AS today
    FROM reminders WHERE user_id = ?
  `).bind(now, start, end, user.id).first();
  const active = Number(row?.active || 0);
  const done = Number(row?.done || 0);
  const total = active + done;
  const progress = total ? Math.round(done * 100 / total) : 0;
  await telegramApi(env, "sendMessage", {
    chat_id: telegramId,
    text: [
      "\u{1F4CA} <b>\u0421\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043A\u0430</b>",
      "",
      `\u{1F4CB} \u0410\u043A\u0442\u0438\u0432\u043D\u0456: <b>${active}</b>`,
      `\u{1F4C5} \u041D\u0430 \u0441\u044C\u043E\u0433\u043E\u0434\u043D\u0456: <b>${Number(row?.today || 0)}</b>`,
      `\u26A0\uFE0F \u041F\u0440\u043E\u0441\u0442\u0440\u043E\u0447\u0435\u043D\u0456: <b>${Number(row?.overdue || 0)}</b>`,
      `\u2705 \u0412\u0438\u043A\u043E\u043D\u0430\u043D\u0456: <b>${done}</b>`,
      `\u{1F4C8} \u0417\u0430\u0433\u0430\u043B\u044C\u043D\u0438\u0439 \u043F\u0440\u043E\u0433\u0440\u0435\u0441: <b>${progress}%</b>`
    ].join("\n"),
    parse_mode: "HTML",
    reply_markup: telegramMainKeyboard(env)
  });
}
__name(sendTelegramStats, "sendTelegramStats");
function parseTelegramDate(value) {
  const text = String(value || "").trim().toLowerCase();
  const now = /* @__PURE__ */ new Date();
  if (text === "\u0441\u044C\u043E\u0433\u043E\u0434\u043D\u0456") return zonedParts(Date.now(), "Europe/Kyiv");
  if (text === "\u0437\u0430\u0432\u0442\u0440\u0430") return addLocalDays(zonedParts(Date.now(), "Europe/Kyiv"), 1);
  let match = text.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  if (match) return { year: Number(match[3]), month: Number(match[2]), day: Number(match[1]), hour: 0, minute: 0, second: 0 };
  match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (match) return { year: Number(match[1]), month: Number(match[2]), day: Number(match[3]), hour: 0, minute: 0, second: 0 };
  return null;
}
__name(parseTelegramDate, "parseTelegramDate");
async function beginTaskCreation(env, telegramId) {
  await setTelegramState(env, telegramId, { step: "title" });
  await telegramApi(env, "sendMessage", {
    chat_id: telegramId,
    text: "\u2795 <b>\u041D\u043E\u0432\u0430 \u0437\u0430\u0434\u0430\u0447\u0430</b>\n\n\u041D\u0430\u043F\u0438\u0448\u0456\u0442\u044C \u043D\u0430\u0437\u0432\u0443 \u0437\u0430\u0434\u0430\u0447\u0456.",
    parse_mode: "HTML",
    reply_markup: { keyboard: [[{ text: "\u274C \u0421\u043A\u0430\u0441\u0443\u0432\u0430\u0442\u0438" }]], resize_keyboard: true, one_time_keyboard: true }
  });
}
__name(beginTaskCreation, "beginTaskCreation");
async function continueTaskCreation(env, message, state) {
  const telegramId = String(message.chat?.id || "");
  const text = String(message.text || "").trim();
  if (text === "\u274C \u0421\u043A\u0430\u0441\u0443\u0432\u0430\u0442\u0438" || /^\/cancel$/i.test(text)) {
    await setTelegramState(env, telegramId, null);
    await sendTelegramMenu(env, telegramId);
    return;
  }
  if (state.step === "title") {
    if (!text) return;
    await setTelegramState(env, telegramId, { ...state, step: "date", title: text.slice(0, 80) });
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "\u{1F4C5} \u0412\u043A\u0430\u0436\u0456\u0442\u044C \u0434\u0430\u0442\u0443: <b>\u0441\u044C\u043E\u0433\u043E\u0434\u043D\u0456</b>, <b>\u0437\u0430\u0432\u0442\u0440\u0430</b> \u0430\u0431\u043E \u0443 \u0444\u043E\u0440\u043C\u0430\u0442\u0456 <b>\u0414\u0414.\u041C\u041C.\u0420\u0420\u0420\u0420</b>.",
      parse_mode: "HTML",
      reply_markup: { keyboard: [[{ text: "\u0421\u044C\u043E\u0433\u043E\u0434\u043D\u0456" }, { text: "\u0417\u0430\u0432\u0442\u0440\u0430" }], [{ text: "\u274C \u0421\u043A\u0430\u0441\u0443\u0432\u0430\u0442\u0438" }]], resize_keyboard: true }
    });
    return;
  }
  if (state.step === "date") {
    const date = parseTelegramDate(text);
    if (!date) {
      await telegramApi(env, "sendMessage", { chat_id: telegramId, text: "\u041D\u0435 \u0440\u043E\u0437\u043F\u0456\u0437\u043D\u0430\u0432 \u0434\u0430\u0442\u0443. \u041D\u0430\u043F\u0440\u0438\u043A\u043B\u0430\u0434: \u0437\u0430\u0432\u0442\u0440\u0430 \u0430\u0431\u043E 18.07.2026" });
      return;
    }
    await setTelegramState(env, telegramId, { ...state, step: "time", date });
    await telegramApi(env, "sendMessage", { chat_id: telegramId, text: "\u23F0 \u0412\u043A\u0430\u0436\u0456\u0442\u044C \u0447\u0430\u0441 \u0443 \u0444\u043E\u0440\u043C\u0430\u0442\u0456 <b>09:30</b>.", parse_mode: "HTML" });
    return;
  }
  if (state.step === "time") {
    const match = text.match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
    if (!match) {
      await telegramApi(env, "sendMessage", { chat_id: telegramId, text: "\u041D\u0435 \u0440\u043E\u0437\u043F\u0456\u0437\u043D\u0430\u0432 \u0447\u0430\u0441. \u041D\u0430\u043F\u0440\u0438\u043A\u043B\u0430\u0434: 09:30" });
      return;
    }
    await setTelegramState(env, telegramId, { ...state, step: "priority", hour: Number(match[1]), minute: Number(match[2]) });
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "\u041E\u0431\u0435\u0440\u0456\u0442\u044C \u043A\u0440\u0438\u0442\u0438\u0447\u043D\u0456\u0441\u0442\u044C:",
      reply_markup: { keyboard: [[{ text: "\u{1F534} \u0412\u0438\u0441\u043E\u043A\u0430" }, { text: "\u{1F7E1} \u0421\u0435\u0440\u0435\u0434\u043D\u044F" }, { text: "\u{1F7E2} \u041D\u0438\u0437\u044C\u043A\u0430" }], [{ text: "\u274C \u0421\u043A\u0430\u0441\u0443\u0432\u0430\u0442\u0438" }]], resize_keyboard: true }
    });
    return;
  }
  if (state.step === "priority") {
    const map = { "\u{1F534} \u0412\u0438\u0441\u043E\u043A\u0430": "high", "\u{1F7E1} \u0421\u0435\u0440\u0435\u0434\u043D\u044F": "medium", "\u{1F7E2} \u041D\u0438\u0437\u044C\u043A\u0430": "low" };
    const priority = map[text];
    if (!priority) return;
    const user = await telegramUser(env, telegramId);
    if (!user) return;
    const dueAt = localPartsToTimestamp({ ...state.date, hour: state.hour, minute: state.minute, second: 0 }, "Europe/Kyiv");
    const now = Date.now();
    const id = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO reminders
      (id, user_id, title, note, due_at, priority, done, sent, item_type, status,
       recurrence_type, recurrence_interval, timezone, created_at, updated_at)
      VALUES (?, ?, ?, '', ?, ?, 0, 0, 'task', 'planned', 'none', 1, 'Europe/Kyiv', ?, ?)
    `).bind(id, user.id, state.title, dueAt, priority, now, now).run();
    await setTelegramState(env, telegramId, null);
    const date = new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone: "Europe/Kyiv" }).format(new Date(dueAt));
    const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Kyiv" }).format(new Date(dueAt));
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: `\u2705 <b>\u0417\u0430\u0434\u0430\u0447\u0443 \u0441\u0442\u0432\u043E\u0440\u0435\u043D\u043E</b>

\u{1F4CB} ${escapeHtml(state.title)}
\u{1F4C5} ${date}
\u23F0 ${time}`,
      parse_mode: "HTML",
      reply_markup: telegramMainKeyboard(env)
    });
  }
}
__name(continueTaskCreation, "continueTaskCreation");
async function handleTelegramMessage(env, message) {
  const telegramId = String(message.chat?.id || "");
  const text = String(message.text || "").trim();
  if (!telegramId) return;
  const state = await getTelegramState(env, telegramId);
  if (state) {
    await continueTaskCreation(env, message, state);
    return;
  }
  if (/^\/start(?:@\w+)?(?:\s|$)/i.test(text) || /^\/menu(?:@\w+)?$/i.test(text)) return handleTelegramStart(env, message);
  if (text === "\u{1F4C5} \u0421\u044C\u043E\u0433\u043E\u0434\u043D\u0456" || /^\/today(?:@\w+)?$/i.test(text)) return sendTelegramList(env, telegramId, "today");
  if (text === "\u{1F4CB} \u0410\u043A\u0442\u0438\u0432\u043D\u0456" || /^\/active(?:@\w+)?$/i.test(text)) return sendTelegramList(env, telegramId, "active");
  if (text === "\u26A0\uFE0F \u041F\u0440\u043E\u0441\u0442\u0440\u043E\u0447\u0435\u043D\u0456" || /^\/overdue(?:@\w+)?$/i.test(text)) return sendTelegramList(env, telegramId, "overdue");
  if (text === "\u2795 \u041D\u043E\u0432\u0430 \u0437\u0430\u0434\u0430\u0447\u0430" || /^\/new(?:@\w+)?$/i.test(text)) return beginTaskCreation(env, telegramId);
  if (text === "\u{1F4CA} \u0421\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043A\u0430" || /^\/stats(?:@\w+)?$/i.test(text)) return sendTelegramStats(env, telegramId);
  if (text === "\u{1F4C2} \u041F\u0440\u043E\u0454\u043A\u0442\u0438") {
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "\u{1F4C2} <b>\u041F\u0440\u043E\u0454\u043A\u0442\u0438</b>\n\n\u0420\u043E\u0437\u0434\u0456\u043B \u0443\u0436\u0435 \u0432 \u043C\u0435\u043D\u044E. \u041F\u0456\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u043D\u044F \u0437\u0430\u0434\u0430\u0447 \u0434\u043E \u043F\u0440\u043E\u0454\u043A\u0442\u0456\u0432 \u0437\u0440\u043E\u0431\u0438\u043C\u043E \u043D\u0430\u0441\u0442\u0443\u043F\u043D\u0438\u043C \u043A\u0440\u043E\u043A\u043E\u043C.",
      parse_mode: "HTML",
      reply_markup: telegramMainKeyboard(env)
    });
    return;
  }
  await sendTelegramMenu(env, telegramId);
}
__name(handleTelegramMessage, "handleTelegramMessage");
async function handleTelegramStart(env, message) {
  const telegramId = String(message.chat?.id || "");
  if (!telegramId) return;
  const user = await telegramUser(env, telegramId);
  if (!user) {
    await telegramApi(env, "sendMessage", {
      chat_id: telegramId,
      text: "\u0421\u043F\u043E\u0447\u0430\u0442\u043A\u0443 \u0443\u0432\u0456\u0439\u0434\u0456\u0442\u044C \u0443 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB \u0447\u0435\u0440\u0435\u0437 Telegram \u043D\u0430 \u0441\u0430\u0439\u0442\u0456.",
      reply_markup: { inline_keyboard: [[{ text: "\u{1F33F} \u0412\u0456\u0434\u043A\u0440\u0438\u0442\u0438 \xAB\u041D\u0430\u0433\u0430\u0434\u0430\u0439\xBB", web_app: { url: appUrl(env) } }]] }
    });
    return;
  }
  await sendTelegramMenu(env, telegramId, user.display_name);
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).bind(`welcome:${user.id}`, String(Date.now())).run();
}
__name(handleTelegramStart, "handleTelegramStart");
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
     WHERE r.id = ? AND u.telegram_id = ?`
  ).bind(reminderId, chatId).first();
  if (!reminder) {
    await answerCallback(env, callbackId, "\u041D\u0430\u0433\u0430\u0434\u0443\u0432\u0430\u043D\u043D\u044F \u043D\u0435 \u0437\u043D\u0430\u0439\u0434\u0435\u043D\u043E", true);
    return;
  }
  const now = Date.now();
  let message = "";
  if (action === "done") {
    await env.DB.prepare(
      "UPDATE reminders SET done = 1, sent = 1, status = 'done', updated_at = ? WHERE id = ? AND user_id = ?"
    ).bind(now, reminder.id, reminder.user_id).run();
    message = `\u2705 <b>\u0412\u0438\u043A\u043E\u043D\u0430\u043D\u043E</b>

${escapeHtml(reminder.title)}`;
    await answerCallback(env, callbackId, "\u041F\u043E\u0437\u043D\u0430\u0447\u0435\u043D\u043E \u0432\u0438\u043A\u043E\u043D\u0430\u043D\u0438\u043C");
  } else if (action === "delay10" || action === "delay60") {
    const minutes = action === "delay10" ? 10 : 60;
    const nextDueAt = now + minutes * 60 * 1e3;
    await env.DB.prepare(
      "UPDATE reminders SET due_at = ?, done = 0, sent = 0, status = 'planned', updated_at = ? WHERE id = ? AND user_id = ?"
    ).bind(nextDueAt, now, reminder.id, reminder.user_id).run();
    const timeZone = normalizeTimeZone(reminder.timezone);
    const nextTime = new Intl.DateTimeFormat("uk-UA", {
      hour: "2-digit",
      minute: "2-digit",
      timeZone
    }).format(new Date(nextDueAt));
    message = `\u23F1 <b>\u0412\u0456\u0434\u043A\u043B\u0430\u0434\u0435\u043D\u043E</b>

${escapeHtml(reminder.title)}

\u041D\u043E\u0432\u0435 \u043D\u0430\u0433\u0430\u0434\u0443\u0432\u0430\u043D\u043D\u044F \u043E <b>${nextTime}</b>`;
    await answerCallback(env, callbackId, `\u0412\u0456\u0434\u043A\u043B\u0430\u0434\u0435\u043D\u043E \u043D\u0430 ${minutes} \u0445\u0432`);
  } else if (action === "tomorrow") {
    const timeZone = normalizeTimeZone(reminder.timezone);
    const current = zonedParts(Number(reminder.due_at), timeZone);
    let nextDueAt = localPartsToTimestamp(addLocalDays(current, 1), timeZone);
    if (nextDueAt <= now) nextDueAt = localPartsToTimestamp(addLocalDays(zonedParts(now, timeZone), 1), timeZone);
    await env.DB.prepare(
      "UPDATE reminders SET due_at = ?, done = 0, sent = 0, status = 'planned', updated_at = ? WHERE id = ? AND user_id = ?"
    ).bind(nextDueAt, now, reminder.id, reminder.user_id).run();
    const date = new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone }).format(new Date(nextDueAt));
    const time = new Intl.DateTimeFormat("uk-UA", { hour: "2-digit", minute: "2-digit", timeZone }).format(new Date(nextDueAt));
    message = `\u{1F4C5} <b>\u041F\u0435\u0440\u0435\u043D\u0435\u0441\u0435\u043D\u043E</b>

${escapeHtml(reminder.title)}

\u041D\u043E\u0432\u0430 \u0434\u0430\u0442\u0430: <b>${date}, ${time}</b>`;
    await answerCallback(env, callbackId, "\u041F\u0435\u0440\u0435\u043D\u0435\u0441\u0435\u043D\u043E \u043D\u0430 \u0437\u0430\u0432\u0442\u0440\u0430");
  } else {
    await answerCallback(env, callbackId, "\u041D\u0435\u0432\u0456\u0434\u043E\u043C\u0430 \u0434\u0456\u044F", true);
    return;
  }
  await editTelegramMessage(env, chatId, messageId, message);
}
__name(handleReminderCallback, "handleReminderCallback");
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
    } else if (update.message) {
      await handleTelegramMessage(env, update.message);
    }
  } catch (error) {
    console.error("Telegram webhook processing failed", error);
  }
  return new Response("OK", { status: 200 });
}
__name(handleTelegramWebhook, "handleTelegramWebhook");
async function connectBot(env, user, origin) {
  try {
    await sendTelegramWelcome(env, user.telegram_id, user.display_name);
    await env.DB.prepare(
      "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(`welcome:${user.id}`, String(Date.now())).run();
    return json({ ok: true, connected: true }, 200, origin);
  } catch (error) {
    return json({
      error: "\u0412\u0456\u0434\u043A\u0440\u0438\u0439\u0442\u0435 \u0431\u043E\u0442\u0430, \u043D\u0430\u0442\u0438\u0441\u043D\u0456\u0442\u044C Start \u0456 \u043F\u043E\u0432\u0442\u043E\u0440\u0456\u0442\u044C \u043F\u0435\u0440\u0435\u0432\u0456\u0440\u043A\u0443",
      code: "BOT_NOT_STARTED"
    }, 409, origin);
  }
}
__name(connectBot, "connectBot");
async function listReminders(env, userId, origin) {
  const { results } = await env.DB.prepare(
    `SELECT id, title, note, due_at, priority, done, sent, item_type, status,
            recurrence_type, recurrence_interval, timezone, created_at, updated_at
     FROM reminders WHERE user_id = ? ORDER BY due_at`
  ).bind(userId).all();
  return json({ reminders: results || [] }, 200, origin);
}
__name(listReminders, "listReminders");
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
       updated_at = excluded.updated_at`
  ).bind(
    id,
    userId,
    title,
    note,
    dueAt,
    priority,
    done,
    done ? 1 : 0,
    itemType,
    status,
    recurrenceType,
    recurrenceInterval,
    timezone,
    now,
    now
  ).run();
  return json({ ok: true, id }, existing ? 200 : 201, origin);
}
__name(upsertReminder, "upsertReminder");
async function processDueReminders(env) {
  const now = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.user_id, r.title, r.note, r.due_at, r.priority, r.item_type, r.status,
            r.recurrence_type, r.recurrence_interval, r.timezone, u.telegram_id
     FROM reminders r JOIN users u ON u.id = r.user_id
     WHERE r.sent = 0 AND r.done = 0 AND r.due_at <= ?
     ORDER BY r.due_at LIMIT 50`
  ).bind(now).all();
  for (const reminder of results || []) {
    try {
      await sendTelegram(env, reminder);
      const nextDueAt = reminder.item_type === "reminder" ? nextOccurrence(reminder, Date.now()) : null;
      if (nextDueAt) {
        await env.DB.prepare(
          "UPDATE reminders SET due_at = ?, sent = 0, updated_at = ? WHERE id = ? AND user_id = ?"
        ).bind(nextDueAt, Date.now(), reminder.id, reminder.user_id).run();
      } else {
        await env.DB.prepare(
          "UPDATE reminders SET sent = 1, updated_at = ? WHERE id = ? AND user_id = ?"
        ).bind(Date.now(), reminder.id, reminder.user_id).run();
      }
    } catch (error) {
      console.error("Failed to send reminder", reminder.id, error);
    }
  }
}
__name(processDueReminders, "processDueReminders");
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
    return origin ? new Response(null, { status: 204, headers: corsHeaders(origin) }) : json({ error: "Origin not allowed" }, 403);
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
__name(handleRequest, "handleRequest");
var index_default = {
  fetch: handleRequest,
  scheduled(_event, env, ctx) {
    ctx.waitUntil(processDueReminders(env));
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-GX6SwE/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = index_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-GX6SwE/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
