// src/routes/uploads.js
import express from "express";
import path from "path";
import { requireAuth, safeParseUrl } from "../middleware/auth.js";
import { query } from "../db.js";
import { BlobServiceClient } from "@azure/storage-blob";

const router = express.Router();

/* ============================================================================
   Helpers
============================================================================ */

// Normalize any filename/blob name for comparison
function normalizeName(input) {
  if (!input) return "";

  let value = String(input);

  // Take only the last segment when the input is a blob path
  value = value.split("/").pop();

  // Decode URL encoding safely
  try {
    value = decodeURIComponent(value);
  } catch {
    // Keep the original value if decoding fails
  }

  value = value.trim().toLowerCase();

  // Remove common timestamp prefixes
  value = value.replace(/^(\d{4}[-]?\d{2}[-]?\d{2}(t?\d{3,})?[_-]+)/i, "");

  // Normalize spaces, underscores, and dashes
  value = value.replace(/[\s_-]+/g, " ");

  // Remove punctuation except the file-extension dot
  value = value.replace(/[^\w.\s]/g, "");

  // Collapse repeated spaces
  value = value.replace(/\s+/g, " ").trim();

  return value;
}

function getContentTypeByExt(filename) {
  const extension = (path.extname(filename || "").toLowerCase() || "").replace(
    ".",
    "",
  );

  const contentTypes = {
    csv: "text/csv",
    txt: "text/plain",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    xls: "application/vnd.ms-excel",
    pdf: "application/pdf",
    json: "application/json",
  };

  return contentTypes[extension] || "application/octet-stream";
}

async function findBlobByLooseName(
  blobServiceClient,
  containers,
  requestedName,
) {
  const requestedNormalizedName = normalizeName(requestedName);

  for (const containerName of containers) {
    const containerClient = blobServiceClient.getContainerClient(containerName);

    if (!(await containerClient.exists())) {
      continue;
    }

    // This scans blobs. Long term, store the exact container/blob name in DB.
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobNormalizedName = normalizeName(blob.name);

      // Exact normalized match
      if (blobNormalizedName === requestedNormalizedName) {
        return {
          containerClient,
          blobName: blob.name,
        };
      }

      // Loose contains match
      if (
        blobNormalizedName.includes(requestedNormalizedName) ||
        requestedNormalizedName.includes(blobNormalizedName)
      ) {
        return {
          containerClient,
          blobName: blob.name,
        };
      }
    }
  }

  return null;
}

function isValidPeriod(value) {
  return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(value || "").trim());
}

function normalizePeriods(period, periods) {
  const values = [];

  if (Array.isArray(periods)) {
    values.push(...periods);
  }

  /*
    Backward compatibility:
    Existing frontend sends a single "period".
    New frontend will send a "periods" array.
  */
  if (period !== null && period !== undefined && String(period).trim() !== "") {
    values.push(period);
  }

  return [
    ...new Set(
      values.map((value) => String(value || "").trim()).filter(Boolean),
    ),
  ].sort();
}

function buildPeriodSummary(periods) {
  if (!periods.length) {
    return null;
  }

  if (periods.length === 1) {
    return periods[0];
  }

  /*
    Report_Number.Period is NVARCHAR(20).
    Individual period values are stored in dbo.Report_Period.
  */
  const range = `${periods[0]} to ${periods[periods.length - 1]}`;

  if (range.length <= 20) {
    return range;
  }

  return `${periods.length} periods`;
}

function isPrivilegedInternalUser(user) {
  const role = String(user?.role || "")
    .toLowerCase()
    .trim();

  return (
    String(user?.user_type || "").toLowerCase() === "internal" &&
    ["admin", "accounting", "ssp_admins"].includes(role)
  );
}

function getUserDisplayName(user) {
  return (
    user?.display_name ||
    user?.fullName ||
    user?.name ||
    user?.username ||
    user?.email ||
    "System"
  );
}

/* ============================================================================
   POST /api/uploads/register

   Supports:
   - Existing payload: period: "2026-07"
   - New payload: periods: ["2026-04", "2026-05", "2026-06"]
   - Locked-period validation
   - Supplier-specific contract validation
   - Report and Accrual upload types
============================================================================ */

router.post("/register", requireAuth, async (req, res) => {
  try {
    let {
      filename,
      report_type = "Sales",
      note = "",
      period = null,
      periods = [],
      bp_code = null,
      contract_id = null,
      related_report_number = null,
    } = req.body || {};

    const user = req.user || {};

    if (!filename) {
      return res.status(400).json({
        error: "Missing filename",
      });
    }

    filename = String(filename).trim();
    report_type = String(report_type || "Sales").trim();
    note = note ? String(note).trim() : "";
    bp_code = bp_code ? String(bp_code).trim() : null;
    contract_id = contract_id ? String(contract_id).trim() : null;

    const normalizedPeriods = normalizePeriods(period, periods);

    if (normalizedPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one period is required",
      });
    }

    const invalidPeriods = normalizedPeriods.filter(
      (selectedPeriod) => !isValidPeriod(selectedPeriod),
    );

    if (invalidPeriods.length > 0) {
      return res.status(400).json({
        error: "Invalid period format",
        details: `Use YYYY-MM format. Invalid period(s): ${invalidPeriods.join(
          ", ",
        )}`,
      });
    }

    if (normalizedPeriods.length > 36) {
      return res.status(400).json({
        error: "Too many periods selected",
        details: "A maximum of 36 periods can be selected for one report.",
      });
    }

    related_report_number =
      related_report_number !== null &&
      related_report_number !== undefined &&
      String(related_report_number).trim() !== ""
        ? Number(related_report_number)
        : null;

    if (
      related_report_number !== null &&
      (!Number.isSafeInteger(related_report_number) ||
        related_report_number <= 0)
    ) {
      return res.status(400).json({
        error: "Invalid related report number",
      });
    }

    const finalBpCode =
      String(user.user_type || "").toLowerCase() === "bp"
        ? user.bp_code || bp_code || null
        : bp_code;

    const uploadedBy =
      String(user.user_type || "").toLowerCase() === "bp"
        ? String(user.email || "").trim()
        : String(user.user_id || user.username || user.email || "").trim();

    if (!uploadedBy) {
      return res.status(401).json({
        error: "Missing user identity",
      });
    }

    const uploadedByName = getUserDisplayName(user);
    const uploadedByType = user.user_type || "internal";
    const periodSummary = buildPeriodSummary(normalizedPeriods);

    /* ------------------------------------------------------------------------
       Check locked periods
    ------------------------------------------------------------------------ */

    const lockedPeriodPlaceholders = normalizedPeriods.map(
      (_, index) => `@p${index + 1}`,
    );

    const lockedPeriodSql = `
      SELECT
        Period AS period
      FROM dbo.Accounting_Period
      WHERE Is_Locked = 1
        AND Period IN (${lockedPeriodPlaceholders.join(", ")});
    `;

    const { rows: lockedPeriods } = await query(
      lockedPeriodSql,
      normalizedPeriods,
    );

    if (lockedPeriods?.length > 0) {
      return res.status(409).json({
        error: "One or more selected periods are locked",
        locked_periods: lockedPeriods.map((item) => item.period),
      });
    }

    /* ------------------------------------------------------------------------
       Check related report number
    ------------------------------------------------------------------------ */

    if (related_report_number !== null) {
      const { rows: relatedReportRows } = await query(
        `
        SELECT TOP 1
          Report_Number AS report_number
        FROM dbo.Report_Number
        WHERE Report_Number = @p1;
        `,
        [related_report_number],
      );

      if (!relatedReportRows?.length) {
        return res.status(400).json({
          error: "Related report number does not exist",
        });
      }
    }

    /* ------------------------------------------------------------------------
       Validate supplier and contract combination
    ------------------------------------------------------------------------ */

    if (contract_id && finalBpCode) {
      const { rows: contractRows } = await query(
        `
        SELECT TOP 1
          Contract_ID AS contract_id,
          BP_Code AS bp_code
        FROM dbo.Ref_Contract
        WHERE Contract_ID = @p1
          AND BP_Code = @p2
          AND Active_Flag = 1;
        `,
        [contract_id, finalBpCode],
      );

      if (!contractRows?.length) {
        return res.status(400).json({
          error: "Selected contract is not valid for the selected supplier",
        });
      }
    }

    console.log("📥 Register Upload Payload:", {
      filename,
      report_type,
      period: periodSummary,
      periods: normalizedPeriods,
      bp_code: finalBpCode,
      contract_id,
      related_report_number,
      user_type: user.user_type,
      uploadedBy,
    });

    /*
      First 10 parameters are used for Report_Number.
      The remaining parameters are used for Report_Period.
    */
    const fixedParams = [
      report_type,
      filename,
      uploadedBy,
      note,
      uploadedByName,
      uploadedByType,
      periodSummary,
      finalBpCode,
      contract_id,
      related_report_number,
    ];

    const periodInsertValues = normalizedPeriods
      .map((_, index) => `(@ReportNumber, @p${fixedParams.length + index + 1})`)
      .join(",\n        ");

    /*
      Report_Number and Report_Period inserts run in one transaction.
      This prevents a report header from being created without periods.
    */
    const sql = `
      SET XACT_ABORT ON;
      BEGIN TRANSACTION;

      BEGIN TRY
        DECLARE @InsertedReport TABLE
        (
          report_number BIGINT,
          report_type NVARCHAR(50),
          filename NVARCHAR(255),
          uploaded_by NVARCHAR(MAX),
          uploaded_by_name NVARCHAR(200),
          uploaded_at_utc DATETIME2(7),
          status NVARCHAR(50),
          uploaded_by_type NVARCHAR(MAX),
          period NVARCHAR(20),
          bp_code NVARCHAR(50),
          contract_id NVARCHAR(50),
          related_report_number BIGINT
        );

        INSERT INTO dbo.Report_Number
        (
          Report_Type,
          Filename,
          Uploaded_By,
          Uploaded_At_UTC,
          Status,
          Note,
          Uploaded_By_Name,
          Uploaded_By_Type,
          Period,
          BP_Code,
          Contract_ID,
          Related_Report_Number
        )
        OUTPUT
          INSERTED.Report_Number,
          INSERTED.Report_Type,
          INSERTED.Filename,
          INSERTED.Uploaded_By,
          INSERTED.Uploaded_By_Name,
          INSERTED.Uploaded_At_UTC,
          INSERTED.Status,
          INSERTED.Uploaded_By_Type,
          INSERTED.Period,
          INSERTED.BP_Code,
          INSERTED.Contract_ID,
          INSERTED.Related_Report_Number
        INTO @InsertedReport
        VALUES
        (
          @p1,
          @p2,
          @p3,
          GETUTCDATE(),
          'new',
          @p4,
          @p5,
          @p6,
          @p7,
          @p8,
          @p9,
          @p10
        );

        DECLARE @ReportNumber BIGINT;

        SELECT TOP 1
          @ReportNumber = report_number
        FROM @InsertedReport;

        INSERT INTO dbo.Report_Period
        (
          Report_Number,
          Period
        )
        VALUES
          ${periodInsertValues};

        COMMIT TRANSACTION;

        SELECT
          report_number,
          report_type,
          filename,
          uploaded_by,
          uploaded_by_name,
          uploaded_at_utc,
          status,
          uploaded_by_type,
          period,
          bp_code,
          contract_id,
          related_report_number
        FROM @InsertedReport;
      END TRY
      BEGIN CATCH
        IF @@TRANCOUNT > 0
        BEGIN
          ROLLBACK TRANSACTION;
        END;

        THROW;
      END CATCH;
    `;

    const params = [...fixedParams, ...normalizedPeriods];

    const { rows } = await query(sql, params);
    const inserted = rows?.[0];

    console.log("✅ Upload registered:", {
      ...inserted,
      periods: normalizedPeriods,
    });

    return res.json({
      success: true,
      data: {
        ...inserted,
        periods: normalizedPeriods,
      },
      report_number: inserted?.report_number,
      status: inserted?.status || "new",
      periods: normalizedPeriods,
      message:
        "Upload registered successfully. Processing will continue through the backend workflow.",
    });
  } catch (err) {
    console.error("❌ /uploads/register error:", err);

    return res.status(500).json({
      error: "Failed to register upload",
      details: err.message,
    });
  }
});

/* ============================================================================
   GET /api/uploads/recent

   Rules:
   - Supplier user: only their uploads
   - Admin, Accounting, SSP Admin: all uploads
   - Other internal users: only their uploads
============================================================================ */

/* ============================================================================
   GET /api/uploads/recent

   Rules:
   - Supplier user: only their uploads
   - Admin, Accounting, SSP Admin: all uploads
   - Other internal users: only their uploads

   Supports:
   - Existing single-period records
   - New multi-period records from Report_Period
   - Friendly display information
   - No duplicate report rows
============================================================================ */

router.get("/recent", requireAuth, async (req, res) => {
  try {
    const url = safeParseUrl(req);
    const requestedReportType = url.searchParams.get("report_type");

    const user = req.user || {};
    const privilegedInternalUser = isPrivilegedInternalUser(user);

    const params = [];
    const filters = [];

    /*
      Supplier and non-privileged internal users should see only
      uploads belonging to them.
    */
    if (!privilegedInternalUser) {
      const uploadedByValue =
        String(user.user_type || "").toLowerCase() === "bp"
          ? String(user.email || "").trim()
          : String(user.user_id || user.username || user.email || "").trim();

      if (!uploadedByValue) {
        return res.status(401).json({
          error: "Missing user identity",
        });
      }

      params.push(uploadedByValue);

      filters.push(`LOWER(rn.Uploaded_By) = LOWER(@p${params.length})`);
    }

    if (requestedReportType) {
      params.push(requestedReportType);

      filters.push(`rn.Report_Type = @p${params.length}`);
    }

    const whereClause =
      filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";

    /*
      OUTER APPLY aggregates all Report_Period rows into one value.
      This prevents one recent-upload row from becoming multiple rows.

      COALESCE falls back to Report_Number.Period for old records that
      were created before Report_Period was introduced.
    */
    const sql = `
      SELECT TOP 20
        rn.Report_Number AS report_number,
        rn.Report_Type AS report_type,
        rn.Filename AS filename,
        rn.Uploaded_By AS uploaded_by,

        ISNULL(
          rn.Uploaded_By_Name,
          rn.Uploaded_By
        ) AS uploaded_by_name,

        rn.Uploaded_At_UTC AS uploaded_at_utc,
        rn.Status AS status,
        rn.Uploaded_By_Type AS uploaded_by_type,

        rn.Period AS period,

        COALESCE(
          NULLIF(period_data.selected_periods, ''),
          rn.Period
        ) AS selected_periods,

        ISNULL(
          period_data.period_count,
          CASE
            WHEN rn.Period IS NULL OR LTRIM(RTRIM(rn.Period)) = ''
              THEN 0
            ELSE 1
          END
        ) AS period_count,

        rn.BP_Code AS bp_code,
        s.Supplier_Name AS supplier_name,
        rn.Contract_ID AS contract_id,
        rn.Related_Report_Number AS related_report_number

      FROM dbo.Report_Number rn

      LEFT JOIN dbo.Ref_Supplier s
        ON s.BP_Code = rn.BP_Code

      OUTER APPLY
      (
        SELECT
          STRING_AGG(
            CAST(rp.Period AS NVARCHAR(MAX)),
            ','
          ) WITHIN GROUP
          (
            ORDER BY rp.Period
          ) AS selected_periods,

          COUNT(*) AS period_count

        FROM dbo.Report_Period rp
        WHERE rp.Report_Number = rn.Report_Number
      ) period_data

      ${whereClause}

      ORDER BY rn.Uploaded_At_UTC DESC;
    `;

    const { rows } = await query(sql, params);

    const items = (rows || []).map((item) => {
      const periods = String(item.selected_periods || "")
        .split(",")
        .map((periodValue) => periodValue.trim())
        .filter(Boolean);

      /*
        Backward-compatible fallback for records that have only
        Report_Number.Period.
      */
      if (
        periods.length === 0 &&
        item.period &&
        /^\d{4}-(0[1-9]|1[0-2])$/.test(String(item.period))
      ) {
        periods.push(String(item.period));
      }

      return {
        ...item,
        periods,
        download_key: item.report_number,
      };
    });

    return res.json({
      items,
    });
  } catch (err) {
    console.error("❌ /uploads/recent error:", err);

    return res.status(500).json({
      error: "Failed to fetch uploads",
      details: err.message,
    });
  }
});

/* ============================================================================
   GET /api/uploads/download/:fileKey

   fileKey can be:
   - Report number
   - Filename
============================================================================ */

router.get("/download/:fileKey", requireAuth, async (req, res) => {
  try {
    const rawKey = req.params.fileKey;

    if (!rawKey) {
      return res.status(400).json({
        error: "Missing file key",
      });
    }

    const decodedKey = (() => {
      try {
        return decodeURIComponent(rawKey).trim();
      } catch {
        return String(rawKey).trim();
      }
    })();

    console.log("📥 [DOWNLOAD] request key:", decodedKey);

    let requestedFilename = decodedKey;

    /*
        When the key is numeric, treat it as Report_Number
        and retrieve the filename from the database.
      */
    if (/^\d+$/.test(decodedKey)) {
      const reportNumber = Number(decodedKey);

      const { rows } = await query(
        `
          SELECT TOP 1
            Filename
          FROM dbo.Report_Number
          WHERE Report_Number = @p1
          ORDER BY Uploaded_At_UTC DESC;
          `,
        [reportNumber],
      );

      if (!rows?.length) {
        return res.status(404).json({
          error: "Report not found",
        });
      }

      requestedFilename = rows[0].Filename;

      console.log(
        "📥 [DOWNLOAD] report_number -> filename:",
        requestedFilename,
      );
    }

    const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;

    if (!connectionString) {
      return res.status(500).json({
        error: "Azure storage connection missing",
      });
    }

    const blobServiceClient =
      BlobServiceClient.fromConnectionString(connectionString);

    const containers = (
      process.env.AZURE_DOWNLOAD_CONTAINERS ||
      "dataintegration,ssp-reports,members,suppliers,internal"
    )
      .split(",")
      .map((container) => container.trim())
      .filter(Boolean);

    const found = await findBlobByLooseName(
      blobServiceClient,
      containers,
      requestedFilename,
    );

    if (!found) {
      console.warn("📥 [DOWNLOAD] NOT FOUND for:", requestedFilename, {
        normalized: normalizeName(requestedFilename),
        containers,
      });

      return res.status(404).json({
        error: "File not found",
      });
    }

    const { containerClient, blobName } = found;

    console.log("📥 [DOWNLOAD] matched blob:", {
      container: containerClient.containerName,
      blobName,
      blobNorm: normalizeName(blobName),
      requestNorm: normalizeName(requestedFilename),
    });

    const blobClient = containerClient.getBlobClient(blobName);

    const download = await blobClient.download();

    const finalName = requestedFilename || blobName.split("/").pop();

    res.setHeader("Content-Disposition", `attachment; filename="${finalName}"`);

    res.setHeader("Content-Type", getContentTypeByExt(finalName));

    download.readableStreamBody.pipe(res);
  } catch (err) {
    console.error("❌ /uploads/download error:", err);

    return res.status(500).json({
      error: "Failed to download file",
    });
  }
});

/* ============================================================================
   GET /api/uploads/lookups/suppliers?q=

   Note:
   The current database has BP_Code, but no Supplier Name column.
   The endpoint still returns display_name for future compatibility.
============================================================================ */

router.get("/lookups/suppliers", requireAuth, async (req, res) => {
  try {
    const searchText = String(req.query.q || "").trim();

    if (searchText.length < 1) {
      return res.json({
        items: [],
      });
    }

    const { rows } = await query(
      `
        SELECT TOP 20
          s.BP_Code AS bp_code,
          s.Supplier_Name AS supplier_name,
          CONCAT(
            s.BP_Code,
            ' - ',
            s.Supplier_Name
          ) AS display_name
        FROM dbo.Ref_Supplier s
        WHERE
          s.Active_Flag = 1
          AND
          (
            s.BP_Code LIKE @p1
            OR s.Supplier_Name LIKE @p1
          )
        ORDER BY
          s.Supplier_Name,
          s.BP_Code;
      `,
      [`%${searchText}%`],
    );

    return res.json({
      items: rows || [],
    });
  } catch (err) {
    console.error("❌ supplier lookup error:", err);

    return res.status(500).json({
      error: "Failed to search suppliers",
      details: err.message,
    });
  }
});

/* ============================================================================
   GET /api/uploads/lookups/contracts?q=&bp_code=

   Supports:
   - Existing contract ID search
   - Supplier-specific contract filtering
   - Default newest active contract
============================================================================ */

router.get("/lookups/contracts", requireAuth, async (req, res) => {
  try {
    const searchText = String(req.query.q || "").trim();

    const bpCode = String(req.query.bp_code || "").trim();

    if (searchText.length < 1 && bpCode.length < 1) {
      return res.json({
        items: [],
        default_contract_id: null,
      });
    }

    const conditions = ["Active_Flag = 1"];

    const params = [];

    if (bpCode) {
      params.push(bpCode);

      conditions.push(`BP_Code = @p${params.length}`);
    }

    if (searchText) {
      params.push(`%${searchText}%`);

      conditions.push(
        `CAST(Contract_ID AS NVARCHAR(255)) LIKE @p${params.length}`,
      );
    }

    const sql = `
        SELECT TOP 50
          Contract_ID AS contract_id,
          CAST(
            Contract_ID AS NVARCHAR(255)
          ) AS contract_name,
          BP_Code AS bp_code,
          Status AS status,
          Effective_From AS effective_from,
          Effective_To AS effective_to,
          Active_Flag AS active_flag
        FROM dbo.Ref_Contract
        WHERE ${conditions.join("\n          AND ")}
        ORDER BY
          Effective_From DESC,
          Effective_To DESC,
          Contract_ID DESC;
      `;

    const { rows } = await query(sql, params);

    const items = (rows || []).map((item, index) => ({
      ...item,
      is_default: index === 0,
    }));

    return res.json({
      items,
      default_contract_id: items[0]?.contract_id || null,
    });
  } catch (err) {
    console.error("❌ contract lookup error:", err);

    return res.status(500).json({
      error: "Failed to search contracts",
    });
  }
});

/* ============================================================================
   GET /api/uploads/periods

   Returns accounting periods and lock status.
============================================================================ */

router.get("/periods", requireAuth, async (_req, res) => {
  try {
    const { rows } = await query(
      `
        SELECT
          Period AS period,
          Is_Locked AS is_locked,
          Locked_By AS locked_by,
          Locked_At_UTC AS locked_at_utc,
          Unlocked_By AS unlocked_by,
          Unlocked_At_UTC AS unlocked_at_utc,
          Created_At_UTC AS created_at_utc,
          Updated_At_UTC AS updated_at_utc
        FROM dbo.Accounting_Period
        ORDER BY Period DESC;
        `,
      [],
    );

    return res.json({
      items: rows || [],
    });
  } catch (err) {
    console.error("❌ periods lookup error:", err);

    return res.status(500).json({
      error: "Failed to fetch accounting periods",
    });
  }
});

/* ============================================================================
   PUT /api/uploads/periods/:period/lock

   Admin, Accounting, and SSP Admin only.
============================================================================ */

router.put("/periods/:period/lock", requireAuth, async (req, res) => {
  try {
    const user = req.user || {};
    const period = String(req.params.period || "").trim();

    if (!isPrivilegedInternalUser(user)) {
      return res.status(403).json({
        error: "Only authorized internal users can lock accounting periods",
      });
    }

    if (!isValidPeriod(period)) {
      return res.status(400).json({
        error: "Invalid period format. Use YYYY-MM.",
      });
    }

    const changedBy = getUserDisplayName(user);

    const { rows } = await query(
      `
        MERGE dbo.Accounting_Period AS target
        USING
        (
          SELECT
            @p1 AS Period
        ) AS source
          ON target.Period = source.Period

        WHEN MATCHED THEN
          UPDATE SET
            Is_Locked = 1,
            Locked_By = @p2,
            Locked_At_UTC = SYSUTCDATETIME(),
            Unlocked_By = NULL,
            Unlocked_At_UTC = NULL,
            Updated_At_UTC = SYSUTCDATETIME()

        WHEN NOT MATCHED THEN
          INSERT
          (
            Period,
            Is_Locked,
            Locked_By,
            Locked_At_UTC,
            Created_At_UTC,
            Updated_At_UTC
          )
          VALUES
          (
            @p1,
            1,
            @p2,
            SYSUTCDATETIME(),
            SYSUTCDATETIME(),
            SYSUTCDATETIME()
          )

        OUTPUT
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Locked_By AS locked_by,
          INSERTED.Locked_At_UTC AS locked_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc;
        `,
      [period, changedBy],
    );

    return res.json({
      success: true,
      data: rows?.[0],
      message: `Period ${period} was locked successfully.`,
    });
  } catch (err) {
    console.error("❌ period lock error:", err);

    return res.status(500).json({
      error: "Failed to lock accounting period",
    });
  }
});

/* ============================================================================
   PUT /api/uploads/periods/:period/unlock

   Admin, Accounting, and SSP Admin only.
============================================================================ */

router.put("/periods/:period/unlock", requireAuth, async (req, res) => {
  try {
    const user = req.user || {};
    const period = String(req.params.period || "").trim();

    if (!isPrivilegedInternalUser(user)) {
      return res.status(403).json({
        error: "Only authorized internal users can unlock accounting periods",
      });
    }

    if (!isValidPeriod(period)) {
      return res.status(400).json({
        error: "Invalid period format. Use YYYY-MM.",
      });
    }

    const changedBy = getUserDisplayName(user);

    const { rows } = await query(
      `
        MERGE dbo.Accounting_Period AS target
        USING
        (
          SELECT
            @p1 AS Period
        ) AS source
          ON target.Period = source.Period

        WHEN MATCHED THEN
          UPDATE SET
            Is_Locked = 0,
            Unlocked_By = @p2,
            Unlocked_At_UTC = SYSUTCDATETIME(),
            Updated_At_UTC = SYSUTCDATETIME()

        WHEN NOT MATCHED THEN
          INSERT
          (
            Period,
            Is_Locked,
            Unlocked_By,
            Unlocked_At_UTC,
            Created_At_UTC,
            Updated_At_UTC
          )
          VALUES
          (
            @p1,
            0,
            @p2,
            SYSUTCDATETIME(),
            SYSUTCDATETIME(),
            SYSUTCDATETIME()
          )

        OUTPUT
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Unlocked_By AS unlocked_by,
          INSERTED.Unlocked_At_UTC AS unlocked_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc;
        `,
      [period, changedBy],
    );

    return res.json({
      success: true,
      data: rows?.[0],
      message: `Period ${period} was unlocked successfully.`,
    });
  } catch (err) {
    console.error("❌ period unlock error:", err);

    return res.status(500).json({
      error: "Failed to unlock accounting period",
    });
  }
});

export default router;
