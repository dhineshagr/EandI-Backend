import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
dotenv.config();

import health from "./routes/health.js";
import auth from "./routes/auth.js";
import users from "./routes/users.js";
import uploads from "./routes/uploads.js";
import reports from "./routes/reports.js";
import sspReportsRoutes from "./routes/sspreports.js";
import notifyAccounting from "./routes/notifyAccounting.js";  // ✅ add this

const app = express();
app.use(helmet());
app.use(express.json({ limit: "5mb" }));
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "*",
    credentials: true,
  })
);
app.use(morgan("dev"));

app.use("/api", health);
app.use("/api/auth", auth);
app.use("/api/users", users);
app.use("/api/uploads", uploads);
app.use("/api", reports);
app.use("/api", sspReportsRoutes);
app.use("/api/notify-accounting", notifyAccounting); // ✅ mount here

// 404
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// error handler
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  res.status(status).json({ error: err.message || "Server error" });
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`API listening on :${port}`));
