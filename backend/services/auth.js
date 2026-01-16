// services/auth.js
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "jwt-secret";

/* ---------- STATEFUL ---------- */

async function loginState({ user, password, session }) {
  if (!user) return false;

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return false;

  session.user = {
    id: user.id,
    role: user.role,
  };

  return true;
}

function requireAdminSession(session) {
  if (!session.user) return null;
  if (session.user.role !== "admin") return null;
  return session.user;
}

/* ---------- STATELESS (JWT) ---------- */

async function loginStateless({ user, password }) {
  if (!user) return null;

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return null;

  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
}

function verifyAdminToken(token) {
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") return null;
    return payload;
  } catch {
    return null;
  }
}

module.exports = {
  loginState,
  requireAdminSession,
  loginStateless,
  verifyAdminToken,
};
