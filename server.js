/* =====================================================
   server.js
   Full patch: resend (Resend API) + server-side rate-limit for /api/send-otp
   Ready to copy-paste.
===================================================== */

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Resend } from "resend";

import { db } from "./db.js";
import { auth } from "./auth.js";
import { streamChat } from "./openai.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const resend = new Resend(process.env.RESEND_API_KEY);

/* ===== Ensure otp_sends tracking table exists =====
   (If you already created it in db.js, this is idempotent)
*/
await db.exec(`
CREATE TABLE IF NOT EXISTS otp_sends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  ip TEXT,
  ts INTEGER
);
`);

/* ===== Keep-alive / healthcheck ===== */
app.get("/ping", (req, res) => res.send("pong"));

/* ===========================
   REGISTER
   - create user (verified=0)
=========================== */
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run("INSERT INTO users (email, password) VALUES (?,?)", [email, hash]);
    return res.json({ ok: true });
  } catch (err) {
    console.error("register err:", err);
    return res.status(400).json({ error: "Email already used" });
  }
});

/* =====================================================
   SEND OTP (with server-side rate-limiting & Resend)
   - MAX_SENDS per WINDOW_MS per email
   - block for BLOCK_MS if exceeded
===================================================== */
const MAX_SENDS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const BLOCK_MS = 15 * 60 * 1000;  // block 15 minutes

app.post("/api/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    // get client IP (support X-Forwarded-For)
    const xf = req.headers['x-forwarded-for'];
    const ip = (xf && xf.split(',').shift().trim()) || req.ip || 'unknown';

    const nowTs = Date.now();
    const windowStart = nowTs - WINDOW_MS;

    // count recent sends for this email
    const recentSends = await db.all(
      "SELECT ts FROM otp_sends WHERE email=? AND ts>? ORDER BY ts DESC",
      [email, windowStart]
    );

    if (recentSends.length >= MAX_SENDS) {
      const lastSendTs = recentSends[0].ts;
      const blockedUntil = lastSendTs + BLOCK_MS;
      if (blockedUntil > nowTs) {
        const retryAfter = Math.ceil((blockedUntil - nowTs)/1000);
        return res.status(429).json({ error: "Too many OTP requests. Try later.", retryAfter });
      }
    }

    // optional: simple IP-based throttle (avoid single-IP spam)
    const recentIp = await db.get(
      "SELECT COUNT(1) AS c FROM otp_sends WHERE ip=? AND ts>?",
      [ip, windowStart]
    );
    if (recentIp && recentIp.c >= (MAX_SENDS * 3)) {
      return res.status(429).json({ error: "Too many requests from this IP" });
    }

    // generate OTP
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = nowTs + 5 * 60 * 1000;

    // remove old OTP for that email and insert new
    await db.run("DELETE FROM otps WHERE email=?", [email]);
    await db.run("INSERT INTO otps (email, code, expires_at) VALUES (?,?,?)", [email, code, expires]);

    // record this send attempt
    await db.run("INSERT INTO otp_sends (email, ip, ts) VALUES (?,?,?)", [email, ip, nowTs]);

    // send email via Resend
    await resend.emails.send({
      from: "Blue Orca AI <onboarding@resend.dev>",
      to: email,
      subject: "Kode Verifikasi Blue Orca",
      html: `
        <div style="font-family: Inter, system-ui, Arial; color:#0b2a44;">
          <h3>Kode OTP Blue Orca</h3>
          <div style="font-size:28px;font-weight:700;margin:10px 0;">${code}</div>
          <p>Berlaku 5 menit. Jika bukan Anda, abaikan email ini.</p>
        </div>
      `
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("send-otp error:", err);
    return res.status(500).json({ error: "Gagal kirim OTP" });
  }
});

/* =====================================================
   VERIFY OTP
===================================================== */
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email & code required" });

    const otp = await db.get("SELECT * FROM otps WHERE email=? AND code=?", [email, code]);
    if (!otp || otp.expires_at < Date.now()) {
      return res.status(400).json({ error: "OTP invalid / expired" });
    }

    await db.run("UPDATE users SET verified=1 WHERE email=?", [email]);
    await db.run("DELETE FROM otps WHERE email=?", [email]);

    return res.json({ ok: true });
  } catch (err) {
    console.error("verify-otp err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/* =====================================================
   LOGIN (returns JWT)
===================================================== */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email & password required" });

    const user = await db.get("SELECT * FROM users WHERE email=?", [email]);
    if (!user) return res.status(400).json({ error: "User not found" });
    if (!user.verified) return res.status(403).json({ error: "Email not verified" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });

    return res.json({ token });
  } catch (err) {
    console.error("login err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/* =====================================================
   CHAT endpoints (auth middleware)
   - create chat
   - stream chat (uses openai.js streamChat)
   - get chats, get messages
===================================================== */
app.post("/api/chat", auth, async (req, res) => {
  try {
    const result = await db.run("INSERT INTO chats (user_id, title) VALUES (?,?)", [req.user.id, "New Chat"]);
    return res.json({ chat_id: result.lastID });
  } catch (err) {
    console.error("create chat err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/chat-stream/:chatId", auth, async (req, res) => {
  try {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Transfer-Encoding", "chunked");

    const { message } = req.body;
    const chatId = req.params.chatId;

    await db.run("INSERT INTO messages (chat_id, role, content) VALUES (?,?,?)", [chatId, "user", message]);

    const history = await db.all("SELECT role, content FROM messages WHERE chat_id=?", [chatId]);

    // capture full assistant response as it's streamed
    let full = "";
    const originalWrite = res.write.bind(res);
    res.write = (chunk) => {
      full += chunk;
      originalWrite(chunk);
    };

    await streamChat(res, history);

    // save assistant reply
    await db.run("INSERT INTO messages (chat_id, role, content) VALUES (?,?,?)", [chatId, "assistant", full]);
    res.end();
  } catch (err) {
    console.error("chat-stream err:", err);
    try { res.end(); } catch {}
  }
});

app.get("/api/chats", auth, async (req, res) => {
  try {
    const chats = await db.all("SELECT * FROM chats WHERE user_id=? ORDER BY created_at DESC", [req.user.id]);
    return res.json(chats);
  } catch (err) {
    console.error("get chats err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/messages/:chatId", auth, async (req, res) => {
  try {
    const msgs = await db.all("SELECT role, content FROM messages WHERE chat_id=?", [req.params.chatId]);
    return res.json(msgs);
  } catch (err) {
    console.error("get messages err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

/* ===== START SERVER ===== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Backend running on port", PORT);
});