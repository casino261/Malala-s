const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.disable("x-powered-by");
app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  connectionTimeoutMillis: 5000
});

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL pool error:", err.message);
});

const JWT_SECRET = process.env.JWT_SECRET;

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token || !JWT_SECRET) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: "ngwin-api",
      audience: "ngwin-player"
    });

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

app.get("/", (req, res) => {
  res.json({
    name: "NGWIN API",
    status: "running",
    mode: process.env.NODE_ENV || "development",
    message: "NGWIN backend API is available."
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "NGWIN API"
  });
});

app.get("/api/health/db", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "healthy",
      database: "connected"
    });
  } catch (err) {
    console.error("Database health check failed:", err.message);

    res.status(503).json({
      status: "unhealthy",
      database: "unavailable"
    });
  }
});

// Initialize tables. Run automatically at startup.
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(30) NOT NULL,
      email VARCHAR(254) NOT NULL,
      password_hash TEXT NOT NULL,
      wallet_balance NUMERIC(18,2) NOT NULL DEFAULT 0.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (username),
      UNIQUE (email),
      CHECK (wallet_balance >= 0)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      player_id BIGINT NOT NULL REFERENCES players(id),
      transaction_type VARCHAR(30) NOT NULL,
      amount NUMERIC(18,2) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      reference VARCHAR(100) UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (amount > 0)
    )
  `);

  console.log("NGWIN database tables are ready.");
}

app.post("/api/auth/register", async (req, res) => {
  const username = typeof req.body.username === "string"
    ? req.body.username.trim()
    : "";

  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  const password = typeof req.body.password === "string"
    ? req.body.password
    : "";

  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({
      error: "Username must be 3-30 characters using letters, numbers or underscores."
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254) {
    return res.status(400).json({
      error: "Enter a valid email address."
    });
  }

  if (password.length < 12 || password.length > 72) {
    return res.status(400).json({
      error: "Password must be 12-72 characters."
    });
  }

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    return res.status(503).json({
      error: "Authentication is not configured."
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO players (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, passwordHash]
    );

    const player = result.rows[0];

    const token = jwt.sign(
      { sub: String(player.id) },
      JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "1h",
        issuer: "ngwin-api",
        audience: "ngwin-player"
      }
    );

    return res.status(201).json({
      message: "Account created successfully.",
      player,
      token
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Username or email is already registered."
      });
    }

    console.error("Registration failed:", err.message);

    return res.status(500).json({
      error: "Unable to create account."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const identifier = typeof req.body.identifier === "string"
    ? req.body.identifier.trim()
    : "";

  const password = typeof req.body.password === "string"
    ? req.body.password
    : "";

  if (!identifier || !password ||
      identifier.length > 254 || password.length > 72) {
    return res.status(400).json({
      error: "Enter your username or email and password."
    });
  }

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    return res.status(503).json({
      error: "Authentication is not configured."
    });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, email, password_hash
       FROM players
       WHERE LOWER(username) = LOWER($1)
          OR email = LOWER($1)
       LIMIT 1`,
      [identifier]
    );

    const player = result.rows[0];

    if (!player ||
        !(await bcrypt.compare(password, player.password_hash))) {
      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    const token = jwt.sign(
      { sub: String(player.id) },
      JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "1h",
        issuer: "ngwin-api",
        audience: "ngwin-player"
      }
    );

    return res.json({
      message: "Login successful.",
      player: {
        id: player.id,
        username: player.username,
        email: player.email
      },
      token
    });
  } catch (err) {
    console.error("Login failed:", err.message);

    return res.status(500).json({
      error: "Unable to log in."
    });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, wallet_balance, created_at
       FROM players
       WHERE id = $1`,
      [req.user.sub]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Player not found."
      });
    }

    return res.json({ player: result.rows[0] });
  } catch (err) {
    console.error("Profile request failed:", err.message);

    return res.status(500).json({
      error: "Unable to retrieve profile."
    });
  }
});

app.get("/api/wallet/transactions", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, transaction_type, amount, status, reference, created_at
       FROM wallet_transactions
       WHERE player_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.sub]
    );

    return res.json({
      transactions: result.rows
    });
  } catch (err) {
    console.error("Transaction history failed:", err.message);

    return res.status(500).json({
      error: "Unable to retrieve transactions."
    });
  }
});

// No public endpoint can directly credit or debit wallets.
// Payment integration and ledger posting will be implemented separately.

app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found"
  });
});

app.use((err, req, res, next) => {
  console.error("Request error:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

const PORT = process.env.PORT || 3000;

let server;

async function start() {
  try {
    await initializeDatabase();

    server = app.listen(PORT, "0.0.0.0", () => {
      console.log(`NGWIN API listening on port ${PORT}`);
    });
  } catch (err) {
    console.error("NGWIN startup failed:", err.message);
    await pool.end();
    process.exit(1);
  }
}

async function shutdown() {
  console.log("Shutting down NGWIN API...");

  if (!server) {
    await pool.end();
    process.exit(0);
    return;
  }

  server.close(async () => {
    try {
      await pool.end();
      process.exit(0);
    } catch (err) {
      console.error("Database shutdown error:", err.message);
      process.exit(1);
    }
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

start();
