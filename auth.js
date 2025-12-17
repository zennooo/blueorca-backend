/* =====================================================
   FILE : auth.js
   FUNGSI :
   - Middleware JWT
===================================================== */

import jwt from "jsonwebtoken";

export function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  try {
    const token = header.split(" ")[1];
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}