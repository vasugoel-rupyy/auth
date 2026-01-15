const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const cors = require("cors");

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
    cookie: {
      httpOnly: true,
      sameSite: "lax", // IMPORTANT
      secure: false, // must be false on http
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

const users = [
  {
    id: 1,
    username: "admin",
    password: bcrypt.hashSync("admin123", 10),
    role: "admin",
  },
  {
    id: 2,
    username: "user",
    password: bcrypt.hashSync("user123", 10),
    role: "user",
  },
];

// Statefull Authentication Route

app.post("/login-stateful", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).send("Invalid credentials");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).send("Invalid credentials");

  req.session.user = {
    id: user.id,
    role: user.role,
  };

  res.send("Logged in (stateful)");
});

app.get("/admin-stateful", (req, res) => {
  console.log("Session:", req.session);
  console.log("Cookies:", req.headers.cookie);

  if (!req.session.user) {
    return res.status(401).send("Not logged in");
  }

  // 2️⃣ Check role
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  // 3️⃣ Authorized
  res.send("Welcome ADMIN (stateful)");
});

// Statless

const JWT_SECRET = "jwt-secret";

app.post("/login-jwt", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).send("Invalid credentials");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).send("Invalid credentials");

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ token });
});

app.get("/admin-jwt", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send("No token");

  const token = auth.split(" ")[1];

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(403).send("Invalid token");
  }

  if (payload.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  res.send("Welcome ADMIN (JWT)");
});

app.listen(3000, () => {
  console.log("Backend running on http://localhost:3000");
});
