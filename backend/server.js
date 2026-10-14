const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

app.disable("x-powered-by");
app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

// PostgreSQL connection using Render environment variables.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  connectionTimeoutMillis: 5000
});

// Report database connection errors without exposing credentials.
pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL pool error:", err.message);
});

// API home
app.get("/", (req, res) => {
  res.json({
    name: "NaijaPlay API",
    status: "running",
    mode: process.env.NODE_ENV || "development",
    message: "NaijaPlay backend API is available."
  });
});

// API health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "NaijaPlay API"
  });
});

// Database health check
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

// Unknown endpoints
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found"
  });
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`NaijaPlay API listening on port ${PORT}`);
});

// Graceful shutdown
async function shutdown() {
  console.log("Shutting down NaijaPlay API...");

  server.close(async () => {
    try {
      await pool.end();
      process.exit(0);
    } catch (err) {
      console.error("Error closing database pool:", err.message);
      process.exit(1);
    }
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
