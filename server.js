require("dotenv").config();
const express      = require("express");
const http         = require("http");
const cors         = require("cors");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const { WebSocketServer } = require("ws");
const jwt          = require("jsonwebtoken");
const bcrypt       = require("bcrypt");
const { Pool }     = require("pg");
const Redis        = require("ioredis");
const Stripe       = require("stripe");
const { v4: uuid } = require("uuid");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });
const pg     = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const redis  = new Redis(process.env.REDIS_URL);
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid token" }); }
};

app.get("/health", (req, res) => res.json({ status: "ok", ts: new Date() }));

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`NEXUS API running on port ${PORT}`));
