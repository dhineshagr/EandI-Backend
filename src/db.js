// src/db.js
import sql from "mssql";
import dotenv from "dotenv";
dotenv.config();

/**
 * Azure SQL Server connection config.
 * Uses explicit fields instead of DATABASE_URL because mssql:// URLs
 * are not supported by the "mssql" library.
 */
const sqlConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  server: process.env.DB_SERVER,
  port: parseInt(process.env.DB_PORT || "1433"),
  options: {
    encrypt: true, // ✅ Always use encryption for Azure SQL
    trustServerCertificate: false, // ✅ Recommended for Azure SQL
  },
};

// ✅ Lazy pool initialization
let poolPromise = null;

/**
 * 🩹 Translate Postgres-style LIMIT N syntax to SQL Server TOP N syntax
 * This allows legacy queries to work until you migrate them fully.
 */
function translateQueryForMSSQL(q) {
  // Replace "SELECT ... LIMIT n" with "SELECT TOP n ..." only if LIMIT appears
  const limitRegex = /\bSELECT\b([\s\S]*?)\bLIMIT\s+(\d+)/i;
  if (limitRegex.test(q)) {
    return q.replace(limitRegex, (match, before, limitNum) => {
      // Insert TOP right after SELECT and remove LIMIT
      return `SELECT TOP ${limitNum}${before}`;
    });
  }
  return q;
}

/**
 * Query helper (keeps same signature as pg)
 * @param {string} q - SQL query (use @p1, @p2 for parameters)
 * @param {Array} params - values for parameters
 * @returns {Object} { rows: [...] }
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
    throw err;
  }
}

/**
 * Optional: test connection at startup
 */
(async () => {
  try {
    const test = await query("SELECT TOP 1 GETDATE() AS now");
    console.log("✅ SQL Server connected:", test.rows[0].now);
  } catch (err) {
    console.error("❌ SQL Server connection failed:", err.message);
  }
})();

/**
 * Compatibility export (for code importing { pool } like pg)
 */
export const pool = {
  query: async (q, params = []) => query(q, params),
};
