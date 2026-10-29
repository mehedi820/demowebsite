const express = require("express");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const SECRET = process.env.JWT_SECRET || "change-this-secret";
const FILE = "db.json";
const load = () => fs.existsSync(FILE)
  ? JSON.parse(fs.readFileSync(FILE)) : { users: [], likes: [] };
const save = (db) => fs.writeFileSync(FILE, JSON.stringify(db, null, 2));

const setToken = (res, email) =>
  res.cookie("token", jwt.sign({ email }, SECRET, { expiresIn: "7d" }),
    { httpOnly: true, sameSite: "lax" });

function auth(req, res, next) {
  try { req.user = jwt.verify(req.cookies.token, SECRET); next(); }
  catch { res.status(401).json({ error: "Login korun" }); }
}

app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6)
    return res.status(400).json({ error: "Email ar 6+ character password din" });
  const db = load();
  if (db.users.find(u => u.email === email))
    return res.status(400).json({ error: "Ei email already ache" });
  db.users.push({ email, hash: await bcrypt.hash(password, 10) });
  save(db);
  setToken(res, email);
  res.json({ email });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = load().users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.hash)))
    return res.status(400).json({ error: "Email ba password bhul" });
  setToken(res, email);
  res.json({ email });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  const likes = load().likes;
  res.json({ email: req.user.email, count: likes.length,
             liked: likes.includes(req.user.email) });
});

app.post("/api/like", auth, (req, res) => {
  const db = load();
  const i = db.likes.indexOf(req.user.email);
  i === -1 ? db.likes.push(req.user.email) : db.likes.splice(i, 1);
  save(db);
  res.json({ count: db.likes.length, liked: i === -1 });
});

app.listen(3000, () => console.log("http://localhost:3000"));
