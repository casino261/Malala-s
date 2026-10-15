"use strict";

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL environment variable.");
  process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must contain at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", (err) => {
  console.error("Unexpected database pool error:", err.message);
});

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "20kb" }));

function createToken(player) {
  return jwt.sign(
    { sub: String(player.id) },
    JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "1h",
      issuer: "ngwin-api",
      audience: "ngwin-player"
    }
  );
}

function requireAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  try {
    req.user = jwt.verify(
      authorization.slice(7).trim(),
      JWT_SECRET,
      {
        algorithms: ["HS256"],
        issuer: "ngwin-api",
        audience: "ngwin-player"
      }
    );

    return next();
  } catch (err) {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(30) NOT NULL UNIQUE,
      email VARCHAR(254) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      wallet_balance NUMERIC(18,2) NOT NULL DEFAULT 0.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT players_wallet_nonnegative
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
      reference VARCHAR(100) UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT wallet_transaction_amount_positive
        CHECK (amount > 0)
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    wallet_transactions_player_created_idx
    ON wallet_transactions (player_id, created_at DESC)
  `);

  console.log("Database initialization completed.");
}

app.get("/", (req, res) => {
  res.json({
    name: "NGWIN API",
    status: "running",
    mode: process.env.NODE_ENV || "production",
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

    return res.json({
      status: "healthy",
      database: "connected"
    });
  } catch (err) {
    console.error("Database health check failed:", err.message);

    return res.status(503).json({
      status: "unhealthy",
      database: "unavailable"
    });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = String(req.body?.username ?? "")
      .trim()
      .toLowerCase();

    const email = String(req.body?.email ?? "")
      .trim()
      .toLowerCase();

    const password = req.body?.password;

    if (!/^[a-z0-9_]{3,30}$/.test(username)) {
      return res.status(400).json({
        error: "Username must contain 3-30 letters, numbers, or underscores."
      });
    }

    if (
      typeof email !== "string" ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "Password must be 12-72 characters long."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO players
        (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, passwordHash]
    );

    const player = result.rows[0];
    const token = createToken(player);

    return res.status(201).json({
      message: "Account created successfully.",
      player,
      token
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    console.error("Registration failed:", err.message);

    return res.status(500).json({
      error: "Unable to create account."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const identifier = String(req.body?.identifier ?? "")
      .trim()
      .toLowerCase();

    const password = req.body?.password;

    if (
      !identifier ||
      typeof password !== "string" ||
      password.length === 0 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "Enter your username or email and password."
      });
    }

    const result = await pool.query(
      `SELECT id, username, email, password_hash
       FROM players
       WHERE LOWER(username) = $1 OR LOWER(email) = $1
       LIMIT 1`,
      [identifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    const player = result.rows[0];
    const matches = await bcrypt.compare(
      password,
      player.password_hash
    );

    if (!matches) {
      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    const token = createToken(player);

    return res.json({
      message: "Login successful.",
      player: {
        id: String(player.id),
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

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Player not found."
      });
    }

    const player = result.rows[0];

    return res.json({
      player: {
        ...player,
        id: String(player.id)
      }
    });
  } catch (err) {
    console.error("Profile retrieval failed:", err.message);

    return res.status(500).json({
      error: "Unable to retrieve profile."
    });
  }
});

app.get("/api/wallet/balance", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT wallet_balance
       FROM players
       WHERE id = $1`,
      [req.user.sub]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Player not found."
      });
    }

    return res.json({
      balance: result.rows[0].wallet_balance,
      currency: "NGN"
    });
  } catch (err) {
    console.error("Wallet balance retrieval failed:", err.message);

    return res.status(500).json({
      error: "Unable to retrieve wallet balance."
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

app.post("/api/wallet/deposits", requireAuth, async (req, res) => {
  try {
    const rawAmount = String(req.body?.amount ?? "").trim();

    if (!/^(?:0|[1-9]\d{0,6})(?:\.\d{1,2})?$/.test(rawAmount)) {
      return res.status(400).json({
        error: "Enter a valid deposit amount."
      });
    }

    const amount = Number(rawAmount);

    if (
      !Number.isFinite(amount) ||
      amount < 1 ||
      amount > 1000000
    ) {
      return res.status(400).json({
        error: "Deposit amount must be between 1 and 1,000,000 NGN."
      });
    }

    const reference = `NGW-DEP-${crypto.randomUUID()}`;

    const result = await pool.query(
      `INSERT INTO wallet_transactions
        (player_id, transaction_type, amount, status, reference)
       VALUES ($1, 'deposit', $2, 'pending', $3)
       RETURNING id, transaction_type, amount, status, reference, created_at`,
      [req.user.sub, rawAmount, reference]
    );

    return res.status(201).json({
      message: "Deposit request created. No payment has been processed.",
      transaction: result.rows[0]
    });
  } catch (err) {
    console.error("Deposit request failed:", err.message);

    return res.status(500).json({
      error: "Unable to create deposit request."
    });
  }
});

app.use((req, res) => {
  return res.status(404).json({
    error: "Endpoint not found."
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON request body."
    });
  }

  console.error("Request error:", err.message);

  return res.status(500).json({
    error: "An unexpected server error occurred."
  });
});

let server;

async function startServer() {
  try {
    await initializeDatabase();

    server = app.listen(PORT, "0.0.0.0", () => {
      console.log(`NGWIN API listening on port ${PORT}`);
    });
  } catch (err) {
    console.error("Server startup failed:", err.message);
    process.exit(1);
  }
}

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down.`);

  if (server) {
    server.close(async () => {
      try {
        await pool.end();
        process.exit(0);
      } catch (err) {
        console.error("Shutdown error:", err.message);
        process.exit(1);
      }
    });
  } else {
    await pool.end();
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

startServer();
