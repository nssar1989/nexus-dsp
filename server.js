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

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid token" }); }
};

// ── HEALTH ─────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok", ts: new Date() }));

// ── AUTH ROUTES ────────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password required" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    const existing = await pg.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length) return res.status(400).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const id = uuid();
    const apiKey = "nxs_" + uuid().replace(/-/g, "");

    await pg.query(
      "INSERT INTO users (id, name, email, password_hash, plan, balance, api_key, created_at) VALUES ($1,$2,$3,$4,'free',0,$5,now())",
      [id, name, email, hash, apiKey]
    );

    const token = jwt.sign({ id, email }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id, name, email, plan: "free", balance: "0.00", api_key: apiKey } });
  } catch (e) {
    console.error("Register error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const result = await pg.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid email or password" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, balance: user.balance, api_key: user.api_key } });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const result = await pg.query("SELECT id, name, email, plan, balance, api_key FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── CAMPAIGNS ─────────────────────────────────────────────────────────────────
app.get("/api/campaigns", auth, async (req, res) => {
  try {
    const result = await pg.query(
      "SELECT * FROM campaigns WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/campaigns", auth, async (req, res) => {
  try {
    const { name, budget, cpm_bid, daily_budget, targeting } = req.body;
    if (!name || !budget || !cpm_bid) return res.status(400).json({ error: "Name, budget and CPM bid required" });

    const id = uuid();
    await pg.query(
      "INSERT INTO campaigns (id, user_id, name, status, budget, spent, cpm_bid, daily_budget, targeting, impressions, clicks, conversions, created_at) VALUES ($1,$2,$3,'active',$4,0,$5,$6,$7,0,0,0,now())",
      [id, req.user.id, name, budget, cpm_bid, daily_budget || budget / 30, JSON.stringify(targeting || {})]
    );

    const result = await pg.query("SELECT * FROM campaigns WHERE id = $1", [id]);
    res.json(result.rows[0]);
  } catch (e) {
    console.error("Campaign create error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.patch("/api/campaigns/:id", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const result = await pg.query(
      "UPDATE campaigns SET status = $1 WHERE id = $2 AND user_id = $3 RETURNING *",
      [status, req.params.id, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Campaign not found" });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── REPORTS ───────────────────────────────────────────────────────────────────
app.get("/api/reports/summary", auth, async (req, res) => {
  try {
    const result = await pg.query(
      "SELECT COALESCE(SUM(spent),0) as spend, COALESCE(SUM(impressions),0) as impressions, COALESCE(SUM(clicks),0) as clicks, COALESCE(SUM(conversions),0) as conversions FROM campaigns WHERE user_id = $1",
      [req.user.id]
    );
    const bids = await pg.query(
      "SELECT COUNT(*) FILTER (WHERE won = true) as bids_won, COUNT(*) FILTER (WHERE won = false) as bids_lost FROM bid_log WHERE user_id = $1",
      [req.user.id]
    ).catch(() => ({ rows: [{ bids_won: 0, bids_lost: 0 }] }));

    res.json({ ...result.rows[0], ...bids.rows[0] });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── BILLING ───────────────────────────────────────────────────────────────────
app.post("/api/billing/topup", auth, async (req, res) => {
  try {
    const { amount_cents } = req.body;
    if (!amount_cents || amount_cents < 1000) return res.status(400).json({ error: "Minimum top-up is $10" });

    const user = await pg.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const u = user.rows[0];

    let customerId = u.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: u.email, name: u.name });
      customerId = customer.id;
      await pg.query("UPDATE users SET stripe_customer_id = $1 WHERE id = $2", [customerId, u.id]);
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount_cents,
      currency: "usd",
      customer: customerId,
      metadata: { user_id: u.id, type: "topup" }
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (e) {
    console.error("Topup error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/billing/subscription", auth, async (req, res) => {
  try {
    const { plan } = req.body;
    const prices = { starter: "price_starter", growth: "price_growth", scale: "price_scale" };
    const priceId = prices[plan];
    if (!priceId) return res.status(400).json({ error: "Invalid plan" });

    const user = await pg.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const u = user.rows[0];

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: u.email,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.FRONTEND_URL}?plan=success`,
      cancel_url: `${process.env.FRONTEND_URL}?plan=cancelled`,
      metadata: { user_id: u.id, plan }
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error("Subscription error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ── OPENRTB BID ENDPOINT ──────────────────────────────────────────────────────
app.post("/openrtb/bid", async (req, res) => {
  try {
    const bidRequest = req.body;
    if (!bidRequest || !bidRequest.imp) return res.status(204).send();

    // Find active campaigns
    const campaigns = await pg.query(
      "SELECT * FROM campaigns WHERE status = 'active' ORDER BY cpm_bid DESC LIMIT 1"
    );

    if (!campaigns.rows.length) return res.status(204).send();

    const campaign = campaigns.rows[0];
    const bidPrice = parseFloat(campaign.cpm_bid);

    const bidResponse = {
      id: bidRequest.id,
      seatbid: [{
        bid: [{
          id: uuid(),
          impid: bidRequest.imp[0].id,
          price: bidPrice,
          adid: campaign.id,
          adm: `<img src="${process.env.API_URL}/win?campaign=${campaign.id}&price=${bidPrice}" width="1" height="1"/>`,
          crid: campaign.id,
          w: bidRequest.imp[0].banner?.w || 300,
          h: bidRequest.imp[0].banner?.h || 250
        }],
        seat: "nexus-dsp"
      }],
      cur: "USD"
    };

    res.json(bidResponse);
  } catch (e) {
    console.error("Bid error:", e);
    res.status(204).send();
  }
});

// Win notification
app.get("/win", async (req, res) => {
  try {
    const { campaign, price } = req.query;
    if (campaign && price) {
      await pg.query(
        "UPDATE campaigns SET spent = spent + $1, impressions = impressions + 1 WHERE id = $2",
        [parseFloat(price) / 1000, campaign]
      );
    }
    res.send("ok");
  } catch (e) {
    res.send("ok");
  }
});

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
wss.on("connection", (ws) => {
  ws.on("message", (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === "ping") ws.send(JSON.stringify({ type: "pong" }));
    } catch (e) {}
  });
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`NEXUS API running on port ${PORT}`));
