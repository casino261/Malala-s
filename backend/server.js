const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const app = express();

app.disable("x-powered-by");
app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

app.get("/", (req, res) => {
  res.json({
    name: "NaijaPlay API",
    status: "running",
    mode: "development",
    message: "NaijaPlay backend API is available."
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "NaijaPlay API"
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found"
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`NaijaPlay API listening on port ${PORT}`);
});
