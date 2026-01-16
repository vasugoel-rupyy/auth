// middlewares/authMiddleware.js
const {
  requireAdminSession,
  verifyAdminToken,
} = require("../services/auth");

/* ---------- STATEFUL ---------- */
function requireAdminStateful(req, res, next) {
  const user = requireAdminSession(req.session);
  if (!user) {
    return res.status(401).send("Not authorized");
  }

  req.user = user; // optional, but useful later
  next();
}

/* ---------- STATELESS ---------- */
function requireAdminJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) {
    return res.status(401).send("No token");
  }

  const token = auth.split(" ")[1];
  const user = verifyAdminToken(token);
  if (!user) {
    return res.status(403).send("Invalid token");
  }

  req.user = user;
  next();
}

module.exports = {
  requireAdminStateful,
  requireAdminJWT,
};
