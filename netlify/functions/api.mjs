// Impact X account API (Netlify Function + Netlify Blobs). No emails, no real names: only a username,
// a salted scrypt password hash, and the player's game progress.
import { getStore } from "@netlify/blobs";
import { randomBytes, scrypt as _scrypt, createHash, timingSafeEqual, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(_scrypt);
export const config = { path: "/api/*" };
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const NAME = /^[a-z0-9_]{3,20}$/, DAY = 86400000, SESSION_DAYS = 30;
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", ...h } });
const sha = (s) => createHash("sha256").update(s).digest("hex");
const hashPw = async (pw, salt = randomBytes(16)) => ({ salt: salt.toString("hex"), hash: (await scrypt(pw, salt, 64, SCRYPT)).toString("hex") });
const check = async (pw, rec) => { const h = await scrypt(pw, Buffer.from(rec.salt, "hex"), 64, SCRYPT), x = Buffer.from(rec.hash, "hex"); return h.length === x.length && timingSafeEqual(h, x); };
const DUMMY = hashPw("dummy-password-for-timing", Buffer.alloc(16));
const cookie = (v, age) => `ix_s=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
const recoveryCode = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = randomBytes(20); let s = ""; for (let i = 0; i < 20; i++) s += A[b[i] % 32]; return s.match(/.{5}/g).join("-"); };
async function limit(st, key, max, ms) { const now = Date.now(); let r = await st.get(key, { type: "json" }); if (!r || now - r.t > ms) r = { n: 0, t: now }; if (r.n >= max) return false; r.n++; await st.setJSON(key, r); return true; }
const clean = (d) => {
  if (!d || typeof d !== "object" || Array.isArray(d)) return null; const o = {};
  const int = (v, lo, hi) => Number.isFinite(v) && v >= lo && v <= hi ? Math.floor(v) : null;
  if (int(d.pts, 0, 1e9) !== null) o.pts = int(d.pts, 0, 1e9);
  if (int(d.eq, 0, 60) !== null) o.eq = int(d.eq, 0, 60);
  if (d.lv && typeof d.lv === "object") { o.lv = {}; for (const k of Object.keys(d.lv).slice(0, 80)) if (/^\d{1,2}-[0-2]$/.test(k) && d.lv[k]) o.lv[k] = 1; }
  for (const k of ["own", "vis"]) if (Array.isArray(d[k])) o[k] = d[k].slice(0, 80).map((v) => int(v, 0, 99)).filter((v) => v !== null);
  if (d.cfg && typeof d.cfg === "object") { o.cfg = {}; for (const k of Object.keys(d.cfg).slice(0, 20)) { const v = d.cfg[k]; if (k.length <= 24 && (typeof v === "number" || typeof v === "boolean" || (typeof v === "string" && v.length <= 40))) o.cfg[k] = v; } }
  return o; // admin flags and unknown fields are never accepted from the browser
};
const GK = { t: 0, k: null };
async function googleKeys() { if (GK.k && Date.now() - GK.t < 3600000) return GK.k; const r = await fetch("https://www.googleapis.com/oauth2/v3/certs"); if (!r.ok) throw new Error("certs"); GK.k = (await r.json()).keys; GK.t = Date.now(); return GK.k; }
export function verifyGoogle(token, aud, keys) { // returns the Google account id (sub) or null
  const parts = String(token || "").split("."); if (parts.length !== 3 || !aud) return null; let h, p;
  try { h = JSON.parse(Buffer.from(parts[0], "base64url")); p = JSON.parse(Buffer.from(parts[1], "base64url")); } catch { return null; }
  if (h.alg !== "RS256") return null; const jwk = (keys || []).find((k) => k.kid === h.kid); if (!jwk) return null;
  try { if (!cryptoVerify("RSA-SHA256", Buffer.from(parts[0] + "." + parts[1]), createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(parts[2], "base64url"))) return null; } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (p.aud !== aud || !["accounts.google.com", "https://accounts.google.com"].includes(p.iss)) return null;
  if (typeof p.sub !== "string" || !p.sub || !(p.exp > now - 30) || (p.iat && p.iat > now + 300)) return null; return p.sub;
}
export default async (req, context) => {
  const url = new URL(req.url), act = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, ""), post = req.method === "POST";
  if (!["GET", "POST"].includes(req.method)) return J({ error: "Method not allowed" }, 405);
  if (post && req.headers.get("origin") !== url.origin) return J({ error: "Blocked: bad origin" }, 403);
  const st = getStore({ name: "impactx", consistency: "strong" }), ip = (context && context.ip) || req.headers.get("x-nf-client-connection-ip") || "unknown";
  let b = {}; if (post) { const t = await req.text(); if (t.length > 30000) return J({ error: "Too large" }, 413); try { b = JSON.parse(t || "{}"); } catch { return J({ error: "Bad request" }, 400); } }
  const uname = (x) => (typeof x === "string" ? x.trim().toLowerCase() : "");
  const sessionOf = async () => { const m = /(?:^|;\s*)ix_s=([a-f0-9]{64})/.exec(req.headers.get("cookie") || ""); if (!m) return null; const k = "s/" + sha(m[1]), s = await st.get(k, { type: "json" }); if (!s) return null; if (s.exp < Date.now()) { await st.delete(k); return null; } return { ...s, k }; };
  const newSession = async (u, rec) => { const tok = randomBytes(32).toString("hex"), h = sha(tok); await st.setJSON("s/" + h, { u, exp: Date.now() + SESSION_DAYS * DAY }); rec.sess = [...(rec.sess || []), h].slice(-5); return tok; };
  try {
    if (act === "me" && !post) { const s = await sessionOf(); if (!s) return J({ user: null }); const d = await st.get("d/" + s.u, { type: "json" }); return J({ user: s.u.startsWith("g_") ? "Google player" : s.u, google: s.u.startsWith("g_"), data: d ? d.data : null }); }
    if (!post) return J({ error: "Not found" }, 404);
    if (act === "register") {
      const u = uname(b.user), pw = typeof b.password === "string" ? b.password : "";
      if (!NAME.test(u)) return J({ error: "Username: 3-20 letters, numbers or _" }, 400);
      if (pw.length < 10 || pw.length > 72 || pw.toLowerCase().includes(u)) return J({ error: "Password must be 10-72 characters and not contain your username" }, 400);
      if (b.agree !== true) return J({ error: "You must accept the Terms and Privacy Policy" }, 400);
      if (!(await limit(st, "r/reg/" + ip, 5, 3600000))) return J({ error: "Too many new accounts from this network. Try later." }, 429);
      if (await st.get("u/" + u, { type: "json" })) return J({ error: "That username is taken" }, 409);
      const code = recoveryCode(), rec = { created: new Date().toISOString(), agreed: new Date().toISOString(), pw: await hashPw(pw), rc: await hashPw(code.replace(/-/g, "")), sess: [] };
      const tok = await newSession(u, rec); await st.setJSON("u/" + u, rec);
      return J({ user: u, recovery: code }, 200, { "set-cookie": cookie(tok, SESSION_DAYS * 86400) });
    }
    if (act === "login") {
      const u = uname(b.user), pw = typeof b.password === "string" ? b.password.slice(0, 200) : "";
      if (!(await limit(st, "r/ip/" + ip, 20, 900000))) return J({ error: "Too many attempts. Wait 15 minutes." }, 429);
      const rec = NAME.test(u) ? await st.get("u/" + u, { type: "json" }) : null, fk = "r/fail/" + u, f = await st.get(fk, { type: "json" });
      if (f && f.n >= 6 && Date.now() - f.t < 900000) return J({ error: "Account temporarily locked. Try again in 15 minutes." }, 429);
      const ok = rec ? await check(pw, rec.pw) : (await check(pw, await DUMMY), false);
      if (!ok) { await st.setJSON(fk, { n: f && Date.now() - f.t < 900000 ? f.n + 1 : 1, t: f && Date.now() - f.t < 900000 ? f.t : Date.now() }); return J({ error: "Wrong username or password" }, 401); }
      await st.delete(fk); const tok = await newSession(u, rec); await st.setJSON("u/" + u, rec);
      return J({ user: u }, 200, { "set-cookie": cookie(tok, SESSION_DAYS * 86400) });
    }
    if (act === "google") {
      const aud = process.env.GOOGLE_CLIENT_ID; if (!aud) return J({ error: "Google sign-in is not set up yet" }, 503);
      if (b.agree !== true) return J({ error: "You must accept the Terms and Privacy Policy" }, 400);
      if (!(await limit(st, "r/g/" + ip, 30, 900000))) return J({ error: "Too many attempts. Wait 15 minutes." }, 429);
      let sub = null; try { sub = verifyGoogle(b.credential, aud, await googleKeys()); } catch { return J({ error: "Could not reach Google. Try again." }, 502); }
      if (!sub) return J({ error: "Google sign-in failed" }, 401);
      const u = "g_" + sha("google:" + sub).slice(0, 24); let rec = await st.get("u/" + u, { type: "json" }); // only a one-way hash of the Google id is stored; never the email or name
      if (!rec) rec = { created: new Date().toISOString(), agreed: new Date().toISOString(), google: true, sess: [] };
      const tok = await newSession(u, rec); await st.setJSON("u/" + u, rec);
      return J({ user: "Google player", google: true }, 200, { "set-cookie": cookie(tok, SESSION_DAYS * 86400) });
    }
    if (act === "logout") { const s = await sessionOf(); if (s) await st.delete(s.k); return J({ ok: true }, 200, { "set-cookie": cookie("", 0) }); }
    if (act === "save") {
      const s = await sessionOf(); if (!s) return J({ error: "Not signed in" }, 401);
      if (!(await limit(st, "r/save/" + s.u, 90, 60000))) return J({ error: "Saving too fast" }, 429);
      const data = clean(b.data); if (!data) return J({ error: "Bad data" }, 400);
      await st.setJSON("d/" + s.u, { data, t: Date.now() }); return J({ ok: true });
    }
    if (act === "recover") {
      const u = uname(b.user), code = typeof b.code === "string" ? b.code.replace(/[^A-Za-z0-9]/g, "").toUpperCase() : "", pw = typeof b.password === "string" ? b.password : "";
      if (!(await limit(st, "r/rec/" + ip, 5, 3600000))) return J({ error: "Too many tries. Wait an hour." }, 429);
      if (pw.length < 10 || pw.length > 72 || pw.toLowerCase().includes(u)) return J({ error: "New password must be 10-72 characters and not contain your username" }, 400);
      const rec = NAME.test(u) ? await st.get("u/" + u, { type: "json" }) : null;
      if (!rec || !(await check(code, rec.rc))) return J({ error: "Username or recovery code is wrong" }, 401);
      for (const h of rec.sess || []) await st.delete("s/" + h);
      const nc = recoveryCode(); rec.pw = await hashPw(pw); rec.rc = await hashPw(nc.replace(/-/g, "")); rec.sess = [];
      const tok = await newSession(u, rec); await st.setJSON("u/" + u, rec);
      return J({ user: u, recovery: nc }, 200, { "set-cookie": cookie(tok, SESSION_DAYS * 86400) });
    }
    if (act === "delete") {
      const s = await sessionOf(); if (!s) return J({ error: "Not signed in" }, 401);
      const rec = await st.get("u/" + s.u, { type: "json" }); if (!rec || (!rec.google && !(await check(typeof b.password === "string" ? b.password : "", rec.pw)))) return J({ error: "Wrong password" }, 401);
      for (const h of rec.sess || []) await st.delete("s/" + h);
      await st.delete("u/" + s.u); await st.delete("d/" + s.u); return J({ ok: true }, 200, { "set-cookie": cookie("", 0) });
    }
    return J({ error: "Not found" }, 404);
  } catch (e) { return J({ error: "Server error" }, 500); }
};
