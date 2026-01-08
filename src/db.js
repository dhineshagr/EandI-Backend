// src/db.js
import sql from "mssql";
import dotenv from "dotenv";
dotenv.config();

/**
 * Azure SQL Server connection config
 */
const sqlConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  server: process.env.DB_SERVER,
  port: parseInt(process.env.DB_PORT || "1433", 10),
  connectionTimeout: 30000,
  requestTimeout: 30000,
  options: {
    encrypt: true,
    trustServerCertificate: process.env.NODE_ENV !== "production",
  },
};

let poolPromise = null;

/**
 * ⚠️ TEMP compatibility shim for legacy LIMIT syntax
 * Logs warning so it can be removed later
 */
function translateQueryForMSSQL(q) {
  const limitRegex = /\bSELECT\b([\s\S]*?)\bLIMIT\s+(\d+)/i;
  if (limitRegex.test(q)) {
    console.warn("⚠️ Legacy LIMIT detected — please migrate query:", q);
    return q.replace(limitRegex, (match, before, limitNum) => {
      return `SELECT TOP ${limitNum}${before}`;
    });
  }
  return q;
}

/**
 * Query helper
 */
export async function query(q, params = []) {
  try {
    if (!poolPromise) {
      poolPromise = sql.connect(sqlConfig);
    }

    const pool = await poolPromise;
    const request = pool.request();
    const sqlText = translateQueryForMSSQL(q);

    params.forEach((val, idx) => {
      request.input(`p${idx + 1}`, val);
    });

    const result = await request.query(sqlText);
    return { rows: result.recordset, recordset: result.recordset };
  } catch (err) {
    console.error("❌ SQL query error:", err.message);

    // Reset pool on fatal errors
    if (
      err.code === "ESOCKET" ||
      err.code === "ETIMEOUT" ||
      err.code === "ECONNCLOSED"
    ) {
      poolPromise = null;
    }

    throw err;
  }
}

/**
 * Startup connectivity test
 */
(async () => {
  try {
    const test = await query("SELECT TOP 1 GETUTCDATE() AS now");
    console.log("✅ SQL Server connected (UTC):", test.rows[0].now);
  } catch (err) {
    console.error("❌ SQL Server connection failed:", err.message);
  }
})();

/**
 * pg-style compatibility export
 */
export const pool = {
  query: async (q, params = []) => query(q, params),
};
