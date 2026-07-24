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
 * Temporary compatibility shim for legacy LIMIT syntax.
 */
function translateQueryForMSSQL(q) {
  const limitRegex = /\bSELECT\b([\s\S]*?)\bLIMIT\s+(\d+)/i;

  if (limitRegex.test(q)) {
    console.warn("⚠️ Legacy LIMIT detected — please migrate query:", q);

    return q.replace(limitRegex, (_match, before, limitNum) => {
      return `SELECT TOP ${limitNum}${before}`;
    });
  }

  return q;
}

/**
 * Returns the shared SQL connection pool.
 */
export async function getPool() {
  try {
    if (!poolPromise) {
      poolPromise = sql.connect(sqlConfig);
    }

    return await poolPromise;
  } catch (error) {
    poolPromise = null;
    throw error;
  }
}

/**
 * Binds positional parameters:
 *
 * @p1, @p2, @p3...
 */
function bindParams(request, params = []) {
  params.forEach((value, index) => {
    request.input(`p${index + 1}`, value);
  });

  return request;
}

/**
 * Standard query helper.
 */
export async function query(q, params = []) {
  try {
    const pool = await getPool();
    const request = bindParams(pool.request(), params);
    const sqlText = translateQueryForMSSQL(q);

    const result = await request.query(sqlText);

    return {
      rows: result.recordset || [],
      recordset: result.recordset || [],
      rowsAffected: result.rowsAffected || [],
      output: result.output || {},
    };
  } catch (error) {
    console.error("❌ SQL query error:", error.message);

    if (
      error.code === "ESOCKET" ||
      error.code === "ETIMEOUT" ||
      error.code === "ECONNCLOSED"
    ) {
      poolPromise = null;
    }

    throw error;
  }
}

/**
 * Runs a query inside an existing SQL transaction.
 */
export async function transactionQuery(transaction, q, params = []) {
  if (!transaction) {
    throw new Error("SQL transaction is required");
  }

  const request = bindParams(new sql.Request(transaction), params);

  const sqlText = translateQueryForMSSQL(q);
  const result = await request.query(sqlText);

  return {
    rows: result.recordset || [],
    recordset: result.recordset || [],
    rowsAffected: result.rowsAffected || [],
    output: result.output || {},
  };
}

/**
 * Executes multiple database operations in one transaction.
 *
 * Usage:
 *
 * const result = await withTransaction(async (txQuery) => {
 *   await txQuery("INSERT ...", [value]);
 *   return await txQuery("UPDATE ...", [value]);
 * });
 */
export async function withTransaction(callback) {
  const pool = await getPool();
  const transaction = new sql.Transaction(pool);

  try {
    await transaction.begin();

    const txQuery = async (q, params = []) => {
      return transactionQuery(transaction, q, params);
    };

    const result = await callback(txQuery, transaction);

    await transaction.commit();

    return result;
  } catch (error) {
    try {
      if (transaction._aborted !== true) {
        await transaction.rollback();
      }
    } catch (rollbackError) {
      console.error(
        "❌ SQL transaction rollback error:",
        rollbackError.message,
      );
    }

    console.error("❌ SQL transaction error:", error.message);

    throw error;
  }
}

/**
 * Startup connectivity test.
 */
(async () => {
  try {
    const test = await query("SELECT TOP 1 GETUTCDATE() AS now");

    console.log("✅ SQL Server connected (UTC):", test.rows[0]?.now);
  } catch (error) {
    console.error("❌ SQL Server connection failed:", error.message);
  }
})();

/**
 * pg-style compatibility export.
 */
export const pool = {
  query: async (q, params = []) => query(q, params),
};
