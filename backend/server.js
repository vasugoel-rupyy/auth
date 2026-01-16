// server.js
const express = require("express");
const session = require("express-session");
const cors = require("cors");

const {
  requireAdminStateful,
  requireAdminJWT,
} = require("./middleware/authMiddleware.js");

const { findUserByUsername } = require("./repositories/userRepositories");
const { loginState, loginStateless } = require("./services/auth");

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5500",
    credentials: true,
  })
);

app.use(
  session({
    name: "sid",
    secret: "stateful-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { sameSite: "lax" },
  })
);

/* ---------- STATEFUL ROUTES ---------- */

app.post("/login-stateful", async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername(username);

  const success = await loginState({
    user,
    password,
    session: req.session,
  });

  if (!success) {
    return res.status(401).send("Invalid credentials");
  }

  res.send("Logged in (stateful)");
});

app.get("/admin-stateful", requireAdminStateful, (req, res) => {
  res.send("Welcome ADMIN (stateful)");
});

/* ---------- STATELESS ROUTES ---------- */

app.post("/login-jwt", async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername(username);

  const token = await loginStateless({ user, password });
  if (!token) {
    return res.status(401).send("Invalid credentials");
  }

  res.json({ token });
});

app.get("/admin-jwt", requireAdminJWT, (req, res) => {
  res.send("Welcome ADMIN (JWT)");
});

app.listen(3000, () => {
  console.log("Backend running on http://localhost:3000");
});
