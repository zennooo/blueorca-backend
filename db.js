import sqlite3 from "sqlite3";
import { open } from "sqlite";

export const db = await open({
  filename: "database.db",
  driver: sqlite3.Database
});

await db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  verified INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS otps (
  email TEXT,
  code TEXT,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER,
  role TEXT,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);