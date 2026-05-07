import { Router } from "express";
import { query } from "../db.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

/* ======================================================================
   Helpers
====================================================================== */
const asInt = (v, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

/* ======================================================================
   REGISTER REPORT (Metadata only)
====================================================================== */
router.post("/reports/register", requireAuth, async (req, res, next) => {
  try {
    const {
      filename,
      report_type = "Sales",
      note = "",
      period = null,
      bp_code = null,
      contract_id = null,
      related_report_number = null,
    } = req.body || {};

    if (!filename) {
      return res.status(400).json({ error: "filename is required" });
    }

    const uploaded_by = req.user?.email || req.user?.username || "unknown@user";

    const uploaded_by_name =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploaded_by_type = req.user?.user_type || "internal";

    const sql = `
      INSERT INTO report_number
        (
          filename,
          report_type,
          uploaded_by,
          uploaded_by_name,
          uploaded_by_type,
          period,
          bp_code,
          contract_id,
          related_report_number,
          uploaded_at_utc,
          status,
          note,
          created_at_utc,
          updated_at_utc
        )
      OUTPUT INSERTED.*
      VALUES
        (
          @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9,
          GETUTCDATE(), 'new', @p10, GETUTCDATE(), GETUTCDATE()
        );
    `;

    const { rows } = await query(sql, [
      filename,
      report_type,
      uploaded_by,
      uploaded_by_name,
      uploaded_by_type,
      period,
      bp_code,
      contract_id,
      related_report_number,
      note,
    ]);

    try {
      await query(
        `INSERT INTO users_audit_log (user_email, action, context_json, created_at_utc)
         VALUES (@p1,'register_report',@p2,GETUTCDATE());`,
        [
          uploaded_by,
          JSON.stringify({
            filename,
            report_type,
            note,
            period,
            bp_code,
            contract_id,
            related_report_number,
          }),
        ],
      );
    } catch {}

    res.json({ report: rows[0] });
  } catch (err) {
    console.error("❌ POST /reports/register error:", err);
    next(err);
  }
});

/* ======================================================================
   LIST REPORTS (Dashboard)
====================================================================== */
router.get("/reports/list", requireAuth, async (_req, res, next) => {
  try {
    const sql = `
      SELECT
        r.report_number,
        r.filename,
        r.report_type,
        r.period,
        r.bp_code,
        r.contract_id,
        r.related_report_number,

        -- keep original values (for debugging / exports)
        r.uploaded_by,
        r.uploaded_at_utc,

        -- ✅ preferred display value for UI
        COALESCE(NULLIF(r.uploaded_by_name, ''), NULLIF(r.uploaded_by, ''), 'System') AS uploaded_by_display,
        r.uploaded_by_name,
        r.uploaded_by_type,

        COUNT(d.cur_detail_id) AS total_rows,
        SUM(CASE WHEN d.dq_status = 'passed' THEN 1 ELSE 0 END) AS passed_count,
        SUM(CASE WHEN d.dq_status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN d.dq_status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
        SUM(CASE WHEN d.dq_status = 'validated' THEN 1 ELSE 0 END) AS validated_count,

        CASE
          -- ✅ ZERO SALES: treat as submitted/approved (no detail rows expected)
          WHEN UPPER(LTRIM(RTRIM(r.filename))) = 'ZERO_SALES'
            OR UPPER(LTRIM(RTRIM(r.filename))) LIKE 'ZERO_SALES%' THEN 'submitted'

          -- Any failed row => Failed
          WHEN SUM(CASE WHEN d.dq_status = 'failed' THEN 1 ELSE 0 END) > 0 THEN 'failed'

          -- All rows approved => Approved
          WHEN COUNT(d.cur_detail_id) > 0
           AND SUM(CASE WHEN d.dq_status = 'approved' THEN 1 ELSE 0 END) = COUNT(d.cur_detail_id) THEN 'approved'

          -- ✅ All rows passed => Passed
          WHEN COUNT(d.cur_detail_id) > 0
           AND SUM(CASE WHEN d.dq_status = 'passed' THEN 1 ELSE 0 END) = COUNT(d.cur_detail_id) THEN 'passed'

          -- Any validated => Validated (only if not failed/approved/passed)
          WHEN SUM(CASE WHEN d.dq_status = 'validated' THEN 1 ELSE 0 END) > 0 THEN 'validated'

          -- ✅ No detail rows yet => Pending
          ELSE 'pending'
        END AS status

      FROM report_number r
      LEFT JOIN cur_invoice_detail d
        ON d.report_number = r.report_number
      GROUP BY
        r.report_number,
        r.filename,
        r.report_type,
        r.period,
        r.bp_code,
        r.contract_id,
        r.related_report_number,
        r.uploaded_by,
        r.uploaded_by_name,
        r.uploaded_by_type,
        r.uploaded_at_utc
      ORDER BY r.uploaded_at_utc DESC;
    `;

    const { rows } = await query(sql);
    res.json({ reports: rows });
  } catch (err) {
    console.error("❌ GET /reports/list error:", err);
    next(err);
  }
});

/* ======================================================================
   REPORT SUMMARY
====================================================================== */
router.get(
  "/reports/:reportNumber/summary",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      if (!rn) return res.status(400).json({ error: "Invalid report number" });

      const sql = `
      SELECT
        report_number,
        COUNT(*) AS total_rows,
        SUM(CASE WHEN dq_status = 'passed' THEN 1 ELSE 0 END) AS passed_count,
        SUM(CASE WHEN dq_status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN dq_status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
        SUM(CASE WHEN dq_status = 'validated' THEN 1 ELSE 0 END) AS validated_count,
        CASE
          WHEN SUM(CASE WHEN dq_status = 'failed' THEN 1 ELSE 0 END) > 0 THEN 'Failed'
          WHEN SUM(CASE WHEN dq_status = 'approved' THEN 1 ELSE 0 END) = COUNT(*) THEN 'Approved'
          WHEN SUM(CASE WHEN dq_status = 'passed' THEN 1 ELSE 0 END) > 0 THEN 'Passed'
          WHEN SUM(CASE WHEN dq_status = 'validated' THEN 1 ELSE 0 END) > 0 THEN 'Validated'
          ELSE 'In Progress'
        END AS report_status
      FROM cur_invoice_detail
      WHERE report_number=@p1
      GROUP BY report_number;
    `;

      const { rows } = await query(sql, [rn]);
      if (!rows.length)
        return res.status(404).json({ error: "Report not found" });

      res.json({ report: rows[0], counts: rows[0] });
    } catch (err) {
      console.error("❌ GET summary error:", err);
      next(err);
    }
  },
);

/* ======================================================================
   DETAIL ROWS
====================================================================== */
router.get(
  "/reports/:reportNumber/rows",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const { status, dq } = req.query;

      let sql = `
      SELECT *
      FROM cur_invoice_detail
      WHERE report_number=@p1
    `;

      const params = [rn];

      if (status) {
        sql += ` AND dq_status=@p${params.length + 1}`;
        params.push(status);
      }

      if (dq) {
        sql += ` AND LOWER(CAST(dq_messages AS NVARCHAR(MAX))) LIKE @p${
          params.length + 1
        }`;
        params.push(`%"${dq.toLowerCase()}"%`);
      }

      sql += `
      ORDER BY cur_detail_id;
    `;

      const { rows } = await query(sql, params);

      res.json({
        rows,
        count: rows.length,
      });
    } catch (err) {
      console.error("❌ GET rows error:", err);
      next(err);
    }
  },
);

/* ======================================================================
   UPDATE SINGLE FIELD + AUDIT
====================================================================== */
router.put(
  "/reports/:reportNumber/row/:curDetailId",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const curDetailId = asInt(req.params.curDetailId);
      const { field_name, new_value, reason } = req.body || {};

      if (!field_name) {
        return res.status(400).json({ error: "field_name required" });
      }

      const { rows: cols } = await query(`
      SELECT column_name
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE table_name='cur_invoice_detail';
    `);

      const allowed = cols.map((c) => c.column_name);
      const readOnly = [
        "cur_detail_id",
        "report_number",
        "approved_by",
        "approved_at_utc",
        "created_at_utc",
        "updated_at_utc",
      ];

      if (!allowed.includes(field_name) || readOnly.includes(field_name)) {
        return res.status(400).json({ error: "Invalid or read-only field" });
      }

      const { rows: oldRows } = await query(
        `SELECT CAST(${field_name} AS NVARCHAR(MAX)) AS old_value
       FROM cur_invoice_detail
       WHERE cur_detail_id=@p1 AND report_number=@p2`,
        [curDetailId, rn],
      );

      if (!oldRows.length)
        return res.status(404).json({ error: "Row not found" });

      const { rows: updRows } = await query(
        `UPDATE cur_invoice_detail
       SET ${field_name}=@p1, updated_at_utc=GETUTCDATE()
       OUTPUT INSERTED.*
       WHERE cur_detail_id=@p2 AND report_number=@p3`,
        [new_value, curDetailId, rn],
      );

      await query(
        `INSERT INTO audit_log
       (report_number,row_key,field_name,old_value,new_value,changed_by,change_reason,changed_at_utc)
       VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,GETUTCDATE())`,
        [
          rn,
          curDetailId,
          field_name,
          oldRows[0].old_value,
          String(new_value ?? ""),
          req.user?.email || "internal",
          reason || "Manual correction",
        ],
      );

      res.json({ ok: true, row: updRows[0] });
    } catch (err) {
      console.error("❌ UPDATE row error:", err);
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * BULK APPROVE (header + details)
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.put(
  "/reports/:reportNumber/approve",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const approver = req.user?.email || "internal";

      const detailUpd = await query(
        `UPDATE cur_invoice_detail
         SET dq_status='approved',
             approved_by=@p1,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         OUTPUT INSERTED.cur_detail_id, INSERTED.dq_status
         WHERE report_number=@p2
           AND dq_status IN ('passed','failed','validated','new','staged');`,
        [approver, rn],
      );

      for (const row of detailUpd.rows) {
        await query(
          `INSERT INTO audit_log
           (report_number, row_key, field_name, old_value, new_value,
            changed_by, change_reason, changed_at_utc)
           VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,'bulk approve',GETUTCDATE());`,
          [rn, row.cur_detail_id, row.dq_status, approver],
        );
      }

      await query(
        `UPDATE cur_invoice_header
         SET report_status='approved',
             approved_by=@p1,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         WHERE report_number=@p2;`,
        [approver, rn],
      );

      await query(
        `UPDATE report_number
         SET status='approved',
             updated_at_utc=GETUTCDATE()
         WHERE report_number=@p1;`,
        [rn],
      );

      try {
        await query(
          `INSERT INTO users_audit_log (user_email, action, context_json, created_at_utc)
           VALUES (@p1,'bulk_approve',@p2,GETUTCDATE());`,
          [approver, JSON.stringify({ report_number: rn })],
        );
      } catch (e) {
        console.warn("users_audit_log skipped:", e.message);
      }

      res.json({
        ok: true,
        approved_rows: detailUpd.rows.length,
        message: `${detailUpd.rows.length} rows approved by ${approver}`,
      });
    } catch (err) {
      console.error("❌ PUT /reports/:reportNumber/approve error:", err);
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * APPROVE A SINGLE ROW
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.put(
  "/reports/:reportNumber/row/:curDetailId/approve",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const curDetailId = asInt(req.params.curDetailId);
      const approver = String(req.user?.email || "internal");

      const { rows: oldRows } = await query(
        `SELECT dq_status
         FROM cur_invoice_detail
         WHERE report_number=@p1 AND cur_detail_id=@p2;`,
        [rn, curDetailId],
      );
      if (!oldRows.length)
        return res.status(404).json({ error: "Row not found" });

      const oldStatus = oldRows[0].dq_status;

      const { rows: updRows } = await query(
        `UPDATE cur_invoice_detail
         SET dq_status='approved',
             approved_by=@p3,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         OUTPUT INSERTED.cur_detail_id, INSERTED.dq_status, INSERTED.approved_by, INSERTED.approved_at_utc
         WHERE report_number=@p1 AND cur_detail_id=@p2;`,
        [rn, curDetailId, approver],
      );

      await query(
        `INSERT INTO audit_log
         (report_number, row_key, field_name, old_value, new_value,
          changed_by, change_reason, changed_at_utc)
         VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,'single approve',GETUTCDATE());`,
        [rn, curDetailId, oldStatus, approver],
      );

      res.json({ ok: true, row: updRows[0] });
    } catch (err) {
      console.error(
        "❌ PUT /reports/:reportNumber/row/:curDetailId/approve error:",
        err,
      );
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * AUDIT LOG (filtering, pagination)
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.get("/:reportNumber/audit-log", requireAuth, async (req, res, next) => {
  try {
    const rn = asInt(req.params.reportNumber);
    const {
      action,
      changed_by,
      start_date,
      end_date,
      limit = 50,
      offset = 0,
      search,
      sort = "changed_at_utc",
      order = "desc",
    } = req.query;

    const allowedSort = ["changed_at_utc", "changed_by", "field_name"];
    const sortCol = allowedSort.includes(sort) ? sort : "changed_at_utc";
    const sortOrder = String(order).toLowerCase() === "asc" ? "ASC" : "DESC";

    let sql = `
      SELECT audit_id, report_number, row_key, field_name, old_value, new_value,
             changed_by, change_reason, changed_at_utc
      FROM audit_log
      WHERE report_number=@p1
    `;
    const params = [rn];

    if (action) {
      sql += ` AND change_reason=@p${params.length + 1}`;
      params.push(action);
    }
    if (changed_by) {
      sql += ` AND LOWER(changed_by) LIKE LOWER(@p${params.length + 1})`;
      params.push(`%${changed_by}%`);
    }
    if (search) {
      const p = `%${search}%`;
      sql += ` AND (LOWER(field_name) LIKE LOWER(@p${params.length + 1})
                    OR LOWER(old_value) LIKE LOWER(@p${params.length + 1})
                    OR LOWER(new_value) LIKE LOWER(@p${params.length + 1}))`;
      params.push(p);
    }
    if (start_date) {
      sql += ` AND changed_at_utc >= @p${params.length + 1}`;
      params.push(start_date);
    }
    if (end_date) {
      sql += ` AND changed_at_utc <= @p${params.length + 1}`;
      params.push(end_date);
    }

    sql += ` ORDER BY ${sortCol} ${sortOrder}
             OFFSET @p${params.length + 1} ROWS FETCH NEXT @p${
               params.length + 2
             } ROWS ONLY;`;
    params.push(offset, limit);

    const { rows } = await query(sql, params);
    res.json({ logs: rows });
  } catch (err) {
    console.error("❌ GET /:reportNumber/audit-log error:", err);
    next(err);
  }
});

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * BACKWARD-COMPATIBLE AUDIT LOG ROUTE
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.get(
  "/reports/:reportNumber/audit-log",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const {
        search = "",
        sort = "changed_at_utc",
        order = "desc",
        limit = 50,
        offset = 0,
      } = req.query;

      const allowedSort = ["changed_at_utc", "changed_by", "field_name"];
      const sortCol = allowedSort.includes(sort) ? sort : "changed_at_utc";
      const sortOrder = order.toLowerCase() === "asc" ? "ASC" : "DESC";

      let sql = `
        SELECT audit_id, report_number, row_key, field_name, old_value, new_value,
               changed_by, change_reason, changed_at_utc
        FROM audit_log
        WHERE report_number=@p1
      `;
      const params = [rn];

      if (search) {
        const p = `%${search}%`;
        sql += ` AND (LOWER(field_name) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(old_value) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(new_value) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(changed_by) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(change_reason) LIKE LOWER(@p${
                       params.length + 1
                     }))`;
        params.push(p);
      }

      sql += ` ORDER BY ${sortCol} ${sortOrder}
               OFFSET @p${params.length + 1} ROWS FETCH NEXT @p${
                 params.length + 2
               } ROWS ONLY;`;
      params.push(offset, limit);

      const { rows } = await query(sql, params);
      res.json({ logs: rows });
    } catch (err) {
      console.error("❌ GET /reports/:reportNumber/audit-log error:", err);
      res.status(500).json({ error: "Failed to fetch report audit log" });
    }
  },
);

router.post("/reports/manual-create", requireAuth, async (req, res, next) => {
  try {
    const {
      report_type,
      period = null,
      bp_code = null,
      contract_id = null,
      related_report_number = null,
      note = "",
      rows = [],
      validation_warnings = [],
      validation_error_details = "",
    } = req.body || {};

    const allowedTypes = ["Accrual", "Return"];

    if (!allowedTypes.includes(report_type)) {
      return res.status(400).json({
        error: "report_type must be Accrual or Return",
      });
    }

    if (!period) {
      return res.status(400).json({ error: "period is required" });
    }

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({
        error: "At least one detail row is required",
      });
    }

    const uploaded_by = req.user?.email || req.user?.username || "unknown@user";

    const uploaded_by_name =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploaded_by_type = req.user?.user_type || "internal";

    const finalBpCode =
      req.user?.user_type === "bp"
        ? req.user?.bp_code || bp_code || null
        : bp_code || null;

    const manualFileName =
      report_type === "Accrual" ? "MANUAL_ACCRUAL" : "MANUAL_RETURN";

    const reportInsertSql = `
      INSERT INTO dbo.Report_Number
      (
        FileName,
        Report_Type,
        Uploaded_By,
        Uploaded_By_Name,
        Uploaded_By_Type,
        Period,
        BP_Code,
        Contract_ID,
        related_report_number,
        Uploaded_At_UTC,
        Status,
        Note,
        Created_At_UTC,
        Updated_At_UTC
      )
      OUTPUT
        INSERTED.Report_Number AS report_number,
        INSERTED.Report_Type AS report_type,
        INSERTED.FileName AS filename,
        INSERTED.Period AS period,
        INSERTED.BP_Code AS bp_code,
        INSERTED.Contract_ID AS contract_id,
        INSERTED.related_report_number AS related_report_number,
        INSERTED.Status AS status
      VALUES
      (
        @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9,
        GETUTCDATE(), 'submitted', @p10, GETUTCDATE(), GETUTCDATE()
      );
    `;

    const { rows: reportRows } = await query(reportInsertSql, [
      manualFileName,
      report_type,
      uploaded_by,
      uploaded_by_name,
      uploaded_by_type,
      period,
      finalBpCode,
      contract_id || null,
      related_report_number || null,
      note || "",
    ]);

    const report = reportRows?.[0];
    const reportNumber = report?.report_number ?? report?.Report_Number ?? null;

    if (!reportNumber) {
      return res.status(500).json({
        error: "Failed to create report header: missing report number",
      });
    }

    await query(
      `
      INSERT INTO dbo.Cur_Invoice_Header
      (
        Report_Number,
        Report_Status,
        Uploaded_By,
        Uploaded_At_UTC,
        Created_At_UTC,
        Updated_At_UTC
      )
      VALUES
      (
        @p1, 'submitted', @p2, GETUTCDATE(), GETUTCDATE(), GETUTCDATE()
      );
      `,
      [reportNumber, uploaded_by],
    );

    const stageSql = `
      INSERT INTO dbo.Stg_Invoice_Raw
      (
        Report_Number,
        Customer_ID,
        Member_Number,
        Member_Name,
        Member_Address,
        Member_City,
        Member_State,
        Member_Zip,
        PO,
        Invoice,
        Invoice_Date,
        Ship_To,
        Ship_To_Address,
        Ship_To_City,
        Ship_To_State,
        Ship_To_Zip,
        Item,
        Manufacturer,
        Manufacturer_Part,
        UM,
        [Desc],
        UNSPSC,
        Category,
        SubCategory,
        Retail_Price,
        Contract_Price,
        Qty,
        Purchase_Dollars,
        CAF,
        CAF_Dollars,
        Created_At_UTC
      )
      VALUES
      (
        @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10,
        @p11, @p12, @p13, @p14, @p15, @p16, @p17, @p18, @p19, @p20,
        @p21, @p22, @p23, @p24, @p25, @p26, @p27, @p28, @p29, @p30,
        GETUTCDATE()
      );
    `;

    for (const row of rows) {
      await query(stageSql, [
        reportNumber,
        row.customer_id || null,
        row.member_number || null,
        row.member_name || null,
        row.member_address || null,
        row.member_city || null,
        row.member_state || null,
        row.member_zip || null,
        row.po || null,
        row.invoice || null,
        row.invoice_date || null,
        row.ship_to || null,
        row.ship_to_address || null,
        row.ship_to_city || null,
        row.ship_to_state || null,
        row.ship_to_zip || null,
        row.item || null,
        row.manufacturer || null,
        row.manufacturer_part || null,
        row.um || null,
        row.desc || row.description || null,
        row.unspsc || null,
        row.category || null,
        row.subcategory || null,
        row.retail_price ?? null,
        row.contract_price ?? null,
        row.qty ?? null,
        row.purchase_dollars ?? row.purchase_dollars_calc ?? null,
        row.caf ?? null,
        row.caf_dollars ?? null,
      ]);
    }

    let trigger_result = null;

    try {
      if (process.env.PIPELINE_TRIGGER_URL) {
        const triggerRes = await fetch(process.env.PIPELINE_TRIGGER_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            report_number: reportNumber,
            report_type,
            period,
            bp_code: finalBpCode,
            contract_id: contract_id || null,
            related_report_number: related_report_number || null,
            source: "manual_ui",
            uploaded_by,
          }),
        });

        trigger_result = {
          ok: triggerRes.ok,
          status: triggerRes.status,
        };
      }
    } catch (triggerErr) {
      trigger_result = {
        ok: false,
        error: triggerErr.message,
      };
    }

    try {
      await query(
        `
        INSERT INTO dbo.Users_Audit_Log
        (
          User_Email,
          Action,
          Context_JSON,
          Created_At_UTC
        )
        VALUES
        (
          @p1,
          'manual_create_report',
          @p2,
          GETUTCDATE()
        );
        `,
        [
          uploaded_by,
          JSON.stringify({
            report_number: reportNumber,
            report_type,
            period,
            bp_code: finalBpCode,
            contract_id: contract_id || null,
            related_report_number: related_report_number || null,
            row_count: rows.length,
            validation_warnings,
            validation_error_details,
            trigger_result,
          }),
        ],
      );
    } catch (auditErr) {
      console.warn("Manual report audit log skipped:", auditErr.message);
    }

    res.json({
      ok: true,
      report_number: reportNumber,
      report,
      row_count: rows.length,
      status: "submitted",
      trigger_result,
      message:
        "Manual report created and staged for validation. Informatica processing will determine final DQ status.",
    });
  } catch (err) {
    console.error("POST /reports/manual-create error:", err);
    next(err);
  }
});

export default router;
