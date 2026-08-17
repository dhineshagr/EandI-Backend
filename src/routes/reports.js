import { Router } from "express";
import { query, withTransaction } from "../db.js";
import { requireAuth, requireAdminOrAccountingDb } from "../middleware/auth.js";

const router = Router();

/* ======================================================================
   Helpers
====================================================================== */
const asInt = (value, defaultValue = 0) => {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : defaultValue;
};

const nullIfEmpty = (value) => {
  if (value === undefined || value === null || String(value).trim() === "") {
    return null;
  }

  return value;
};

const nullableNumber = (value) => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const numericValue = Number(value);

  return Number.isFinite(numericValue) ? numericValue : null;
};

const reverseAmount = (value) => {
  const numericValue = nullableNumber(value);

  return numericValue === null ? null : numericValue * -1;
};

const validateOpenPeriods = async (periods, queryFn = query) => {
  const normalizedPeriods = Array.from(
    new Set(
      (Array.isArray(periods) ? periods : [])
        .map((value) => String(value || "").trim())
        .filter(Boolean),
    ),
  );

  if (normalizedPeriods.length === 0) {
    return;
  }

  const placeholders = normalizedPeriods
    .map((_, index) => `@p${index + 1}`)
    .join(", ");

  /*
   * Business rule:
   *
   * Period not found in dbo.Accounting_Period = open
   * Is_Locked = 0                           = open
   * Is_Locked = 1                           = closed
   */
  const { rows } = await queryFn(
    `
    SELECT
      Period AS period,
      Is_Locked AS is_locked,
      Locked_By AS locked_by,
      Locked_At_UTC AS locked_at_utc
    FROM dbo.Accounting_Period
    WHERE Is_Locked = 1
      AND Period IN (${placeholders});
    `,
    normalizedPeriods,
  );

  const lockedPeriods = (rows || [])
    .map((row) => String(row.period || "").trim())
    .filter(Boolean);

  if (lockedPeriods.length > 0) {
    const error = new Error(
      `The following accounting period(s) are closed: ${lockedPeriods.join(
        ", ",
      )}.`,
    );

    error.statusCode = 400;
    error.code = "ACCOUNTING_PERIOD_CLOSED";
    error.periods = lockedPeriods;

    throw error;
  }
};

// ============================================================
// ACCOUNTING PERIOD HELPERS
// ============================================================

/**
 * Accepts YYYY-MM only.
 *
 * Valid:
 *   2026-01
 *   2026-12
 *
 * Invalid:
 *   01-2026
 *   2026-1
 *   July 2026
 */
function normalizeAccountingPeriod(value) {
  const period = String(value || "").trim();

  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) {
    return null;
  }

  return period;
}

/**
 * Returns the current logged-in user's best available identifier.
 *
 * Update these property names if your /me endpoint uses different fields.
 */
function getCurrentUserIdentifier(req) {
  return (
    req.user?.email ||
    req.user?.username ||
    req.user?.display_name ||
    req.session?.user?.email ||
    req.session?.user?.username ||
    req.session?.user?.display_name ||
    "Unknown User"
  );
}

/**
 * Checks whether the current user is an internal user.
 *
 * Business Partner users have user_type = "bp".
 */
function isInternalUser(req) {
  const userType = String(
    req.user?.user_type || req.session?.user?.user_type || "",
  )
    .trim()
    .toLowerCase();

  return userType !== "bp";
}

function isBpUser(req) {
  return (
    String(req.user?.user_type || "")
      .trim()
      .toLowerCase() === "bp"
  );
}

function getBpCode(req) {
  return String(req.user?.bp_code || "").trim();
}

function normalizePeriods(periods = [], legacyPeriod = null) {
  return Array.from(
    new Set(
      [
        ...(Array.isArray(periods) ? periods : []),
        ...(legacyPeriod ? [legacyPeriod] : []),
      ]
        .map((value) => String(value || "").trim())
        .filter(Boolean),
    ),
  ).sort((left, right) => left.localeCompare(right));
}

function getInvalidAccountingPeriods(periods) {
  return (periods || []).filter((period) => !normalizeAccountingPeriod(period));
}

function sendInvalidPeriodResponse(res, invalidPeriods) {
  return res.status(400).json({
    error: "Accounting periods must use YYYY-MM format",
    code: "INVALID_ACCOUNTING_PERIOD",
    periods: invalidPeriods,
  });
}

async function verifyReportAccess(req, reportNumber, queryFn = query) {
  if (!reportNumber) {
    const error = new Error("Invalid report number");
    error.statusCode = 400;
    error.code = "INVALID_REPORT_NUMBER";
    throw error;
  }

  const { rows } = await queryFn(
    `
    SELECT TOP 1
      Report_Number AS report_number,
      BP_Code AS bp_code,
      Report_Type AS report_type,
      Status AS status
    FROM dbo.Report_Number
    WHERE Report_Number = @p1;
    `,
    [reportNumber],
  );

  if (!rows.length) {
    const error = new Error("Report not found");
    error.statusCode = 404;
    error.code = "REPORT_NOT_FOUND";
    throw error;
  }

  const report = rows[0];

  if (isBpUser(req)) {
    const userBpCode = getBpCode(req);
    const reportBpCode = String(report.bp_code || "").trim();

    if (
      !userBpCode ||
      userBpCode.toLowerCase() !== reportBpCode.toLowerCase()
    ) {
      const error = new Error("You do not have access to this report");
      error.statusCode = 403;
      error.code = "REPORT_ACCESS_DENIED";
      throw error;
    }
  }

  return report;
}

function sendRouteError(res, next, error) {
  if (error?.statusCode) {
    return res.status(error.statusCode).json({
      error: error.message,
      code: error.code || "REQUEST_FAILED",
    });
  }

  return next(error);
}

const editableDetailFields = new Set([
  "customer_id",
  "member_number",
  "member_name",
  "member_address",
  "member_city",
  "member_state",
  "member_zip",
  "matched_member_number",
  "po",
  "invoice",
  "invoice_date",
  "ship_to",
  "ship_to_address",
  "ship_to_city",
  "ship_to_state",
  "ship_to_zip",
  "item",
  "manufacturer",
  "manufacturer_part",
  "um",
  "description",
  "unspsc",
  "category",
  "subcategory",
  "retail_price",
  "contract_price",
  "qty",
  "purchase_dollars",
  "caf",
]);

/**
 * Middleware used by the period-management write APIs.
 *
 * All internal users are allowed.
 */
function requireInternalAccountingPeriodAccess(req, res, next) {
  if (!req.user && !req.session?.user) {
    return res.status(401).json({
      success: false,
      code: "UNAUTHENTICATED",
      message: "Authentication is required.",
    });
  }

  if (!isInternalUser(req)) {
    return res.status(403).json({
      success: false,
      code: "INTERNAL_USER_REQUIRED",
      message: "Only internal users can manage accounting periods.",
    });
  }

  return next();
}
/* ======================================================================
   REGISTER REPORT (Metadata only)
====================================================================== */
/* ======================================================================
   REGISTER REPORT (Metadata only)
   - Supports legacy single period
   - Supports multiple periods
   - Stores a summary value in Report_Number.Period
   - Stores one row per period in Report_Period
====================================================================== */
router.post("/reports/register", requireAuth, async (req, res, next) => {
  try {
    const {
      filename,
      report_type = "Members",
      note = "",
      period = null,
      periods = [],
      bp_code = null,
      contract_id = null,
      related_report_number = null,
    } = req.body || {};

    if (!String(filename || "").trim()) {
      return res.status(400).json({ error: "filename is required" });
    }

    const normalizedPeriods = normalizePeriods(periods, period);

    if (normalizedPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one accounting period is required",
        code: "ACCOUNTING_PERIOD_REQUIRED",
        periods: [],
      });
    }

    const invalidPeriods = getInvalidAccountingPeriods(normalizedPeriods);
    if (invalidPeriods.length > 0) {
      return sendInvalidPeriodResponse(res, invalidPeriods);
    }

    const resolvedBpCode = isBpUser(req)
      ? getBpCode(req)
      : nullIfEmpty(typeof bp_code === "string" ? bp_code.trim() : bp_code);

    if (isBpUser(req) && !resolvedBpCode) {
      return res.status(403).json({
        error: "A supplier code is not assigned to this Business Partner user",
        code: "BP_CODE_REQUIRED",
      });
    }

    const relatedReportNumber = related_report_number
      ? asInt(related_report_number)
      : null;

    if (related_report_number && !relatedReportNumber) {
      return res.status(400).json({
        error: "related_report_number must be a positive integer",
      });
    }

    if (relatedReportNumber) {
      await verifyReportAccess(req, relatedReportNumber);
    }

    await validateOpenPeriods(normalizedPeriods);

    const periodSummary = normalizedPeriods.join(", ");
    const uploadedBy = req.user?.email || req.user?.username || "unknown@user";
    const uploadedByName =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");
    const uploadedByType = req.user?.user_type || "internal";

    const result = await withTransaction(async (txQuery) => {
      const { rows: reportRows } = await txQuery(
        `
        INSERT INTO dbo.Report_Number
        (
          FileName, Report_Type, Uploaded_By, Uploaded_By_Name,
          Uploaded_By_Type, Period, BP_Code, Contract_ID,
          Related_Report_Number, Uploaded_At_UTC, Status, Note,
          Created_At_UTC, Updated_At_UTC
        )
        OUTPUT
          INSERTED.Report_Number AS report_number,
          INSERTED.FileName AS filename,
          INSERTED.Report_Type AS report_type,
          INSERTED.Period AS period,
          INSERTED.BP_Code AS bp_code,
          INSERTED.Contract_ID AS contract_id,
          INSERTED.Related_Report_Number AS related_report_number,
          INSERTED.Uploaded_By AS uploaded_by,
          INSERTED.Uploaded_By_Name AS uploaded_by_name,
          INSERTED.Uploaded_By_Type AS uploaded_by_type,
          INSERTED.Uploaded_At_UTC AS uploaded_at_utc,
          INSERTED.Status AS status,
          INSERTED.Note AS note
        VALUES
        (
          @p1, @p2, @p3, @p4, @p5, @p6, @p7,
          @p8, @p9, GETUTCDATE(), 'new', @p10,
          GETUTCDATE(), GETUTCDATE()
        );
        `,
        [
          String(filename).trim(),
          report_type,
          uploadedBy,
          uploadedByName,
          uploadedByType,
          periodSummary,
          resolvedBpCode,
          nullIfEmpty(contract_id),
          relatedReportNumber,
          note || "",
        ],
      );

      const report = reportRows?.[0];
      const reportNumber = report?.report_number;

      if (!reportNumber) {
        throw new Error("Failed to register report");
      }

      for (const selectedPeriod of normalizedPeriods) {
        await txQuery(
          `
    INSERT INTO dbo.Report_Period
    (
      Report_Number,
      Period,
      Created_At_UTC
    )
    VALUES
    (
      @p1,
      @p2,
      GETUTCDATE()
    );
    `,
          [reportNumber, selectedPeriod],
        );
      }

      try {
        await txQuery(
          `
          INSERT INTO dbo.Users_Audit_Log
          (User_Email, Action, Context_JSON, Created_At_UTC)
          VALUES (@p1, 'register_report', @p2, GETUTCDATE());
          `,
          [
            uploadedBy,
            JSON.stringify({
              report_number: reportNumber,
              filename: String(filename).trim(),
              report_type,
              note,
              period: periodSummary,
              periods: normalizedPeriods,
              bp_code: resolvedBpCode,
              contract_id: nullIfEmpty(contract_id),
              related_report_number: relatedReportNumber,
            }),
          ],
        );
      } catch (auditError) {
        console.warn("Register report audit log skipped:", auditError.message);
      }

      return { report, reportNumber };
    });

    return res.json({
      ok: true,
      report: {
        ...result.report,
        period: periodSummary,
        periods: normalizedPeriods,
      },
    });
  } catch (error) {
    console.error("❌ POST /reports/register error:", error);
    return sendRouteError(res, next, error);
  }
});

/* ======================================================================
   LIST REPORTS (Dashboard)

   PERIOD MODEL
   ----------------------------------------------------------------------
   Report Period:
   - Report_Number.Period = display summary
   - Report_Period = selected Report Period values

   Posting Period:
   - Posting_Period_Start = range start
   - Posting_Period = range end / NetSuite posting period

   Other existing behavior preserved:
   - Supplier filtering
   - Multiple Report Periods
   - Status calculations
   - Zero Sales behavior
   - Purchase / CAF totals
   - Detail counts
   - BP access
====================================================================== */

router.get("/reports/list", requireAuth, async (req, res, next) => {
  try {
    const sql = `
      SELECT
        r.Report_Number AS report_number,

        r.FileName AS filename,

        r.Report_Type AS report_type,


        /* ================================================================
           REPORT PERIOD
        ================================================================ */

        COALESCE(
          NULLIF(r.Period, ''),
          NULLIF(period_data.selected_periods, '')
        ) AS period,


        /* ================================================================
           POSTING PERIOD
        ================================================================ */

        r.Posting_Period_Start
          AS posting_period_start,

        r.Posting_Period
          AS posting_period,


        /* ================================================================
           SUPPLIER / CONTRACT
        ================================================================ */

        r.BP_Code AS bp_code,

        s.Supplier_Name AS supplier_name,

        r.Contract_ID AS contract_id,

        r.Related_Report_Number
          AS related_report_number,


        /* ================================================================
           UPLOAD INFORMATION
        ================================================================ */

        r.Uploaded_By AS uploaded_by,

        r.Uploaded_At_UTC AS uploaded_at_utc,

        COALESCE(
          NULLIF(r.Uploaded_By_Name, ''),
          NULLIF(r.Uploaded_By, ''),
          'System'
        ) AS uploaded_by_display,

        r.Uploaded_By_Name
          AS uploaded_by_name,

        r.Uploaded_By_Type
          AS uploaded_by_type,


        /* ================================================================
           COUNTS
        ================================================================ */

        COUNT(
          d.Cur_Detail_ID
        ) AS total_rows,


        SUM(
          CASE
            WHEN LOWER(
              COALESCE(
                d.DQ_Status,
                ''
              )
            ) = 'passed'
            THEN 1
            ELSE 0
          END
        ) AS passed_count,


        SUM(
          CASE
            WHEN LOWER(
              COALESCE(
                d.DQ_Status,
                ''
              )
            ) = 'failed'
            THEN 1
            ELSE 0
          END
        ) AS failed_count,


        SUM(
          CASE
            WHEN LOWER(
              COALESCE(
                d.DQ_Status,
                ''
              )
            ) = 'approved'
            THEN 1
            ELSE 0
          END
        ) AS approved_count,


        SUM(
          CASE
            WHEN LOWER(
              COALESCE(
                d.DQ_Status,
                ''
              )
            ) = 'validated'
            THEN 1
            ELSE 0
          END
        ) AS validated_count,


        /* ================================================================
           TOTAL PURCHASE
        ================================================================ */

        COALESCE(
          SUM(
            TRY_CAST(
              d.Purchase_Dollars_Calc
                AS DECIMAL(19, 2)
            )
          ),
          0
        ) AS total_purchase,


        /* ================================================================
           TOTAL CAF
        ================================================================ */

        COALESCE(
          SUM(
            TRY_CAST(
              d.CAF_Dollars
                AS DECIMAL(19, 2)
            )
          ),
          0
        ) AS total_caf,


        /* ================================================================
           STATUS
        ================================================================ */

        CASE

          /* --------------------------------------------------------------
             ZERO SALES
          -------------------------------------------------------------- */

          WHEN UPPER(
            LTRIM(
              RTRIM(
                r.FileName
              )
            )
          ) = 'ZERO_SALES'

            OR UPPER(
              LTRIM(
                RTRIM(
                  r.FileName
                )
              )
            ) LIKE 'ZERO_SALES%'

          THEN 'submitted'


          /* --------------------------------------------------------------
             EXPLICIT APPROVED STATUS
          -------------------------------------------------------------- */

          WHEN LOWER(
            COALESCE(
              NULLIF(
                r.Status,
                ''
              ),
              ''
            )
          ) = 'approved'

          THEN 'approved'


          /* --------------------------------------------------------------
             FAILED ROW EXISTS
          -------------------------------------------------------------- */

          WHEN SUM(
            CASE
              WHEN LOWER(
                COALESCE(
                  d.DQ_Status,
                  ''
                )
              ) = 'failed'
              THEN 1
              ELSE 0
            END
          ) > 0

          THEN 'failed'


          /* --------------------------------------------------------------
             ALL ROWS APPROVED
          -------------------------------------------------------------- */

          WHEN COUNT(
            d.Cur_Detail_ID
          ) > 0

          AND SUM(
            CASE
              WHEN LOWER(
                COALESCE(
                  d.DQ_Status,
                  ''
                )
              ) = 'approved'
              THEN 1
              ELSE 0
            END
          ) = COUNT(
            d.Cur_Detail_ID
          )

          THEN 'approved'


          /* --------------------------------------------------------------
             ALL ROWS PASSED
          -------------------------------------------------------------- */

          WHEN COUNT(
            d.Cur_Detail_ID
          ) > 0

          AND SUM(
            CASE
              WHEN LOWER(
                COALESCE(
                  d.DQ_Status,
                  ''
                )
              ) = 'passed'
              THEN 1
              ELSE 0
            END
          ) = COUNT(
            d.Cur_Detail_ID
          )

          THEN 'passed'


          /* --------------------------------------------------------------
             VALIDATED ROWS
          -------------------------------------------------------------- */

          WHEN SUM(
            CASE
              WHEN LOWER(
                COALESCE(
                  d.DQ_Status,
                  ''
                )
              ) = 'validated'
              THEN 1
              ELSE 0
            END
          ) > 0

          THEN 'validated'


          /* --------------------------------------------------------------
             PRESERVE CURRENT PROCESSING STATUS
          -------------------------------------------------------------- */

          WHEN LOWER(
            COALESCE(
              NULLIF(
                r.Status,
                ''
              ),
              ''
            )
          ) IN
          (
            'new',
            'staged',
            'submitted',
            'pending',
            'processing'
          )

          THEN LOWER(
            r.Status
          )


          /* --------------------------------------------------------------
             DEFAULT
          -------------------------------------------------------------- */

          ELSE 'pending'

        END AS status


      FROM dbo.Report_Number r


      /* ==================================================================
         SUPPLIER
      ================================================================== */

      LEFT JOIN dbo.Ref_Supplier s

        ON s.BP_Code =
           r.BP_Code


      /* ==================================================================
         DETAIL ROWS
      ================================================================== */

      LEFT JOIN dbo.Cur_Invoice_Detail d

        ON d.Report_Number =
           r.Report_Number


      /* ==================================================================
         REPORT PERIODS

         Aggregate first so detail rows are not duplicated.
      ================================================================== */

      OUTER APPLY
      (
        SELECT

          STRING_AGG(
            CAST(
              period_rows.Period
                AS NVARCHAR(50)
            ),
            ', '
          ) AS selected_periods

        FROM
        (
          SELECT DISTINCT

            rp.Period

          FROM dbo.Report_Period rp

          WHERE
            rp.Report_Number =
              r.Report_Number

            AND rp.Period
              IS NOT NULL

            AND LTRIM(
                  RTRIM(
                    CAST(
                      rp.Period
                        AS NVARCHAR(50)
                    )
                  )
                ) <> ''

        ) period_rows

      ) period_data


      /* ==================================================================
         BP SECURITY
      ================================================================== */

      WHERE
        (
          @p1 = 0

          OR LOWER(
               LTRIM(
                 RTRIM(
                   r.BP_Code
                 )
               )
             )
             =
             LOWER(
               @p2
             )
        )


      /* ==================================================================
         GROUP BY
      ================================================================== */

      GROUP BY

        r.Report_Number,

        r.FileName,

        r.Report_Type,

        r.Period,

        r.Posting_Period_Start,

        r.Posting_Period,

        period_data.selected_periods,

        r.BP_Code,

        s.Supplier_Name,

        r.Contract_ID,

        r.Related_Report_Number,

        r.Uploaded_By,

        r.Uploaded_By_Name,

        r.Uploaded_By_Type,

        r.Uploaded_At_UTC,

        r.Status


      ORDER BY
        r.Uploaded_At_UTC DESC;
    `;

    /* ====================================================================
       BP ACCESS
    ==================================================================== */

    const bpOnly = isBpUser(req) ? 1 : 0;

    const bpCode = isBpUser(req) ? getBpCode(req) : "";

    if (isBpUser(req) && !bpCode) {
      return res.status(403).json({
        error: "A supplier code is not assigned to this Business Partner user",

        code: "BP_CODE_REQUIRED",
      });
    }

    /* ====================================================================
       EXECUTE
    ==================================================================== */

    const { rows } = await query(sql, [bpOnly, bpCode]);

    /* ====================================================================
       FORMAT RESPONSE
    ==================================================================== */

    const reports = rows.map((report) => {
      /* --------------------------------------------------------------
             REPORT PERIODS

             Prefer the Report_Period rows.

             Example:
               "2026-01, 2026-03"

             becomes:
               ["2026-01", "2026-03"]
          -------------------------------------------------------------- */

      let periods = [];

      if (report.period) {
        const periodValue = String(report.period).trim();

        /*
         * New range summary:
         *
         * 2026-01 to 2026-03
         */
        if (periodValue.includes(" to ")) {
          periods = periodValue
            .split(" to ")
            .map((value) => value.trim())
            .filter(Boolean);
        } else {
          /*
           * Existing comma-separated format.
           */
          periods = periodValue
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean);
        }
      }

      periods = Array.from(new Set(periods)).sort((left, right) =>
        left.localeCompare(right),
      );

      return {
        ...report,

        periods,

        /*
         * Explicit new period fields.
         */
        posting_period_start: report.posting_period_start || null,

        posting_period: report.posting_period || null,

        total_purchase: Number(report.total_purchase || 0),

        total_caf: Number(report.total_caf || 0),
      };
    });

    /* ====================================================================
       RESPONSE
    ==================================================================== */

    return res.json({
      reports,
    });
  } catch (err) {
    console.error("❌ GET /reports/list error:", err);

    next(err);
  }
});

/* ======================================================================
   MEMBER LOOKUP
   GET /reports/member-lookup?q=000005

   Purpose:
   - Search Ref_Member by Member Number or Member Name.
   - Supports leading-zero normalization.
   - Returns results for the Selected Member Number dropdown.
   - Admin and Accounting users only.
====================================================================== */

router.get(
  "/reports/member-lookup",
  requireAuth,
  requireAdminOrAccountingDb,
  async (req, res, next) => {
    try {
      const searchValue = String(req.query?.q || "").trim();

      /*
       * Do not execute a full-table search when no search value was supplied.
       */
      if (!searchValue) {
        return res.status(200).json({
          success: true,
          count: 0,
          items: [],
        });
      }

      /*
       * Keep the lookup responsive and prevent very large responses.
       */
      const requestedLimit = Number(req.query?.limit);

      const limit = Number.isInteger(requestedLimit)
        ? Math.min(50, Math.max(1, requestedLimit))
        : 20;

      const containsSearch = `%${searchValue}%`;
      const startsWithSearch = `${searchValue}%`;

      const { rows } = await query(
        `
        SELECT TOP (@p4)
          member.Member_ID AS member_id,
          member.External_ID AS external_id,
          member.Member_Number AS member_number,
          member.Member_Name AS member_name,
          member.Status AS status,
          member.Effective_From AS effective_from,
          member.Effective_To AS effective_to,

          member.Member_Address AS member_address,
          member.Member_City AS member_city,
          member.Member_State AS member_state,
          member.Member_Zip AS member_zip,

          member.Ship_To_Name AS ship_to_name,
          member.Ship_To_Address AS ship_to_address,
          member.Ship_To_City AS ship_to_city,
          member.Ship_To_State AS ship_to_state,
          member.Ship_To_Zip AS ship_to_zip

        FROM dbo.Ref_Member member

        WHERE
          /*
           * Exact Member Number.
           */
          LTRIM(RTRIM(COALESCE(member.Member_Number, ''))) = @p1

          /*
           * Member Number with leading-zero normalization.
           *
           * Examples:
           *   Search 5      matches 000005
           *   Search 2315   matches 002315
           */
          OR
          (
            TRY_CONVERT(
              BIGINT,
              LTRIM(RTRIM(member.Member_Number))
            ) IS NOT NULL

            AND TRY_CONVERT(
              BIGINT,
              LTRIM(RTRIM(@p1))
            ) IS NOT NULL

            AND TRY_CONVERT(
              BIGINT,
              LTRIM(RTRIM(member.Member_Number))
            ) = TRY_CONVERT(
              BIGINT,
              LTRIM(RTRIM(@p1))
            )
          )

          /*
           * Partial Member Number.
           */
          OR LTRIM(
               RTRIM(
                 COALESCE(member.Member_Number, '')
               )
             ) LIKE @p2

          /*
           * Partial Member Name.
           */
          OR LTRIM(
               RTRIM(
                 COALESCE(member.Member_Name, '')
               )
             ) LIKE @p2

        ORDER BY
          /*
           * 1. Exact Member Number.
           */
          CASE
            WHEN LTRIM(
                   RTRIM(
                     COALESCE(member.Member_Number, '')
                   )
                 ) = @p1
              THEN 0
            ELSE 1
          END,

          /*
           * 2. Leading-zero normalized exact match.
           */
          CASE
            WHEN
              TRY_CONVERT(
                BIGINT,
                LTRIM(RTRIM(member.Member_Number))
              ) IS NOT NULL

              AND TRY_CONVERT(
                BIGINT,
                LTRIM(RTRIM(@p1))
              ) IS NOT NULL

              AND TRY_CONVERT(
                BIGINT,
                LTRIM(RTRIM(member.Member_Number))
              ) = TRY_CONVERT(
                BIGINT,
                LTRIM(RTRIM(@p1))
              )
              THEN 0
            ELSE 1
          END,

          /*
           * 3. Member Number beginning with the search value.
           */
          CASE
            WHEN LTRIM(
                   RTRIM(
                     COALESCE(member.Member_Number, '')
                   )
                 ) LIKE @p3
              THEN 0
            ELSE 1
          END,

          /*
           * 4. Current or continuing records first.
           */
          CASE
            WHEN member.Effective_To IS NULL
              THEN 0
            WHEN member.Effective_To >= CAST(GETUTCDATE() AS DATE)
              THEN 1
            ELSE 2
          END,

          /*
           * 5. Newest effective record.
           */
          member.Effective_To DESC,
          member.Effective_From DESC,

          member.Member_Number,
          member.Member_Name;
        `,
        [searchValue, containsSearch, startsWithSearch, limit],
      );

      const items = (rows || []).map((member) => ({
        member_id: member.member_id || null,
        external_id: member.external_id || null,

        member_number: String(member.member_number || "").trim(),
        member_name: String(member.member_name || "").trim(),

        status: member.status || null,
        effective_from: member.effective_from || null,
        effective_to: member.effective_to || null,

        member_address: member.member_address || null,
        member_city: member.member_city || null,
        member_state: member.member_state || null,
        member_zip: member.member_zip || null,

        ship_to_name: member.ship_to_name || null,
        ship_to_address: member.ship_to_address || null,
        ship_to_city: member.ship_to_city || null,
        ship_to_state: member.ship_to_state || null,
        ship_to_zip: member.ship_to_zip || null,
      }));

      return res.status(200).json({
        success: true,
        count: items.length,
        items,
      });
    } catch (error) {
      console.error("❌ GET /reports/member-lookup error:", error);

      return sendRouteError(res, next, error);
    }
  },
);

/* ======================================================================
   REPORT SUMMARY
====================================================================== */
/* ======================================================================
   REPORT SUMMARY
   - Returns report header metadata
   - Returns DQ counts
   - Supports multiple periods
   - Supports legacy Report_Number.Period fallback
   - Supports Zero Sales reports with no detail rows
====================================================================== */
router.get(
  "/reports/:reportNumber/summary",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);

      if (!rn) {
        return res.status(400).json({ error: "Invalid report number" });
      }

      await verifyReportAccess(req, rn);

      const sql = `
        SELECT
          r.Report_Number AS report_number,
          r.FileName AS filename,
          r.Report_Type AS report_type,

          COALESCE(
            NULLIF(period_data.selected_periods, ''),
            NULLIF(r.Period, '')
          ) AS period,

          r.BP_Code AS bp_code,
          s.Supplier_Name AS supplier_name,
          r.Contract_ID AS contract_id,
          r.Related_Report_Number AS related_report_number,

          r.Uploaded_By AS uploaded_by,
          r.Uploaded_By_Name AS uploaded_by_name,
          r.Uploaded_By_Type AS uploaded_by_type,
          r.Uploaded_At_UTC AS uploaded_at_utc,

          COALESCE(
            NULLIF(r.Uploaded_By_Name, ''),
            NULLIF(r.Uploaded_By, ''),
            'System'
          ) AS uploaded_by_display,

          COUNT(d.Cur_Detail_ID) AS total_rows,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
                THEN 1
              ELSE 0
            END
          ) AS passed_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
                THEN 1
              ELSE 0
            END
          ) AS failed_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
                THEN 1
              ELSE 0
            END
          ) AS approved_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
                THEN 1
              ELSE 0
            END
          ) AS validated_count,

          /* Purchase total for this report */
          COALESCE(
            SUM(
              TRY_CAST(
                d.Purchase_Dollars_Calc AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS purchase_total,

          /* CAF total for this report */
          COALESCE(
            SUM(
              TRY_CAST(
                d.CAF_Dollars AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS caf_total,

          CASE
            /*
             * Zero Sales reports do not contain detail rows.
             */
            WHEN UPPER(LTRIM(RTRIM(r.FileName))) = 'ZERO_SALES'
              OR UPPER(LTRIM(RTRIM(r.FileName))) LIKE 'ZERO_SALES%'
              THEN 'submitted'

            /*
             * Prefer the explicit approved header status.
             */
            WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) = 'approved'
              THEN 'approved'

            /*
             * Any failed detail row means the report failed.
             */
            WHEN SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
                  THEN 1
                ELSE 0
              END
            ) > 0
              THEN 'failed'

            /*
             * Every detail row approved.
             */
            WHEN COUNT(d.Cur_Detail_ID) > 0
              AND SUM(
                CASE
                  WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
                    THEN 1
                  ELSE 0
                END
              ) = COUNT(d.Cur_Detail_ID)
              THEN 'approved'

            /*
             * Every detail row passed.
             */
            WHEN COUNT(d.Cur_Detail_ID) > 0
              AND SUM(
                CASE
                  WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
                    THEN 1
                  ELSE 0
                END
              ) = COUNT(d.Cur_Detail_ID)
              THEN 'passed'

            /*
             * At least one detail row validated.
             */
            WHEN SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
                  THEN 1
                ELSE 0
              END
            ) > 0
              THEN 'validated'

            /*
             * Preserve an existing processing status.
             */
            WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) IN
              (
                'new',
                'staged',
                'submitted',
                'pending',
                'processing'
              )
              THEN LOWER(r.Status)

            ELSE 'pending'
          END AS report_status

        FROM dbo.Report_Number r

        LEFT JOIN dbo.Ref_Supplier s
          ON s.BP_Code = r.BP_Code

        LEFT JOIN dbo.Cur_Invoice_Detail d
          ON d.Report_Number = r.Report_Number

        OUTER APPLY (
          SELECT
            STRING_AGG(
              CAST(period_rows.Period AS NVARCHAR(50)),
              ', '
            ) AS selected_periods
          FROM (
            SELECT DISTINCT
              rp.Period
            FROM dbo.Report_Period rp
            WHERE rp.Report_Number = r.Report_Number
              AND rp.Period IS NOT NULL
              AND LTRIM(
                RTRIM(
                  CAST(rp.Period AS NVARCHAR(50))
                )
              ) <> ''
          ) period_rows
        ) period_data

        WHERE r.Report_Number = @p1

        GROUP BY
          r.Report_Number,
          r.FileName,
          r.Report_Type,
          r.Period,
          period_data.selected_periods,
          r.BP_Code,
          s.Supplier_Name,
          r.Contract_ID,
          r.Related_Report_Number,
          r.Uploaded_By,
          r.Uploaded_By_Name,
          r.Uploaded_By_Type,
          r.Uploaded_At_UTC,
          r.Status;
      `;

      const { rows } = await query(sql, [rn]);

      if (!rows.length) {
        return res.status(404).json({
          error: "Report not found",
        });
      }

      const row = rows[0];

      const periods = String(row.period || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);

      const report = {
        report_number: row.report_number,
        filename: row.filename,
        report_type: row.report_type,
        period: row.period || null,
        periods,
        bp_code: row.bp_code || null,
        supplier_name: row.supplier_name || null,
        contract_id: row.contract_id || null,
        related_report_number: row.related_report_number || null,
        uploaded_by: row.uploaded_by || null,
        uploaded_by_name: row.uploaded_by_name || null,
        uploaded_by_type: row.uploaded_by_type || null,
        uploaded_by_display: row.uploaded_by_display || "System",
        uploaded_at_utc: row.uploaded_at_utc || null,
        report_status: row.report_status,
      };

      const counts = {
        total_rows: Number(row.total_rows || 0),
        passed_count: Number(row.passed_count || 0),
        failed_count: Number(row.failed_count || 0),
        approved_count: Number(row.approved_count || 0),
        validated_count: Number(row.validated_count || 0),
      };

      const totals = {
        purchase_total: Number(row.purchase_total || 0),
        caf_total: Number(row.caf_total || 0),
      };

      return res.json({
        report,
        counts,
        totals,
      });
    } catch (err) {
      console.error("❌ GET /reports/:reportNumber/summary error:", err);

      return sendRouteError(res, next, err);
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

      if (!rn) {
        return res.status(400).json({ error: "Invalid report number" });
      }

      await verifyReportAccess(req, rn);

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
      return sendRouteError(res, next, err);
    }
  },
);

/* ======================================================================
   UPDATE SINGLE FIELD + AUDIT
====================================================================== */
/* ======================================================================
   UPDATE SINGLE FIELD + AUDIT

   Special behavior:
   - Editing Matched_Member_Number looks up Ref_Member.
   - Automatically populates Matched_Member_Name.
   - Original Member_Number and Member_Name remain unchanged.
====================================================================== */

router.put(
  "/reports/:reportNumber/row/:curDetailId",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const curDetailId = asInt(req.params.curDetailId);

      const fieldName = String(req.body?.field_name || "")
        .trim()
        .toLowerCase();

      const { new_value, reason } = req.body || {};

      if (!rn) {
        return res.status(400).json({
          error: "Invalid report number",
        });
      }

      if (!curDetailId) {
        return res.status(400).json({
          error: "Invalid detail row ID",
        });
      }

      if (!fieldName) {
        return res.status(400).json({
          error: "field_name required",
        });
      }

      if (!editableDetailFields.has(fieldName)) {
        return res.status(400).json({
          error: "Invalid or read-only field",
        });
      }

      await verifyReportAccess(req, rn);

      const changedBy = getCurrentUserIdentifier(req);

      const result = await withTransaction(async (txQuery) => {
        /*
         * Special processing for selected matched member.
         */
        if (fieldName === "matched_member_number") {
          const selectedMemberNumber = String(new_value ?? "").trim();

          const { rows: currentRows } = await txQuery(
            `
            SELECT
              Matched_Member_Number AS matched_member_number,
              Matched_Member_Name AS matched_member_name
            FROM dbo.Cur_Invoice_Detail
            WHERE Cur_Detail_ID = @p1
              AND Report_Number = @p2;
            `,
            [curDetailId, rn],
          );

          if (!currentRows.length) {
            const error = new Error("Row not found");
            error.statusCode = 404;
            error.code = "DETAIL_ROW_NOT_FOUND";
            throw error;
          }

          const oldMatchedNumber = currentRows[0].matched_member_number ?? "";

          const oldMatchedName = currentRows[0].matched_member_name ?? "";

          /*
           * Clearing the selected member clears both matched values.
           */
          if (!selectedMemberNumber) {
            const { rows: clearedRows } = await txQuery(
              `
              UPDATE dbo.Cur_Invoice_Detail
              SET
                Matched_Member_Number = NULL,
                Matched_Member_Name = NULL,
                Updated_At_UTC = GETUTCDATE()
              OUTPUT INSERTED.*
              WHERE Cur_Detail_ID = @p1
                AND Report_Number = @p2;
              `,
              [curDetailId, rn],
            );

            await txQuery(
              `
              INSERT INTO dbo.Audit_Log
              (
                Report_Number,
                Row_Key,
                Field_Name,
                Old_Value,
                New_Value,
                Changed_By,
                Change_Reason,
                Changed_At_UTC
              )
              VALUES
              (
                @p1,
                @p2,
                'matched_member_number',
                @p3,
                '',
                @p4,
                @p5,
                GETUTCDATE()
              );
              `,
              [
                rn,
                curDetailId,
                String(oldMatchedNumber),
                changedBy,
                reason || "Matched member selection cleared",
              ],
            );

            await txQuery(
              `
              INSERT INTO dbo.Audit_Log
              (
                Report_Number,
                Row_Key,
                Field_Name,
                Old_Value,
                New_Value,
                Changed_By,
                Change_Reason,
                Changed_At_UTC
              )
              VALUES
              (
                @p1,
                @p2,
                'matched_member_name',
                @p3,
                '',
                @p4,
                @p5,
                GETUTCDATE()
              );
              `,
              [
                rn,
                curDetailId,
                String(oldMatchedName),
                changedBy,
                reason || "Matched member selection cleared",
              ],
            );

            return clearedRows[0];
          }

          /*
           * Normalize leading zeros when matching.
           *
           * Examples:
           *   000145 matches 145
           *   002315 matches 2315
           */
          const { rows: memberRows } = await txQuery(
            `
            SELECT TOP 1
              Member_Number AS member_number,
              Member_Name AS member_name
            FROM dbo.Ref_Member
            WHERE
              LTRIM(RTRIM(Member_Number)) = @p1

              OR
              (
                TRY_CONVERT(BIGINT, LTRIM(RTRIM(Member_Number)))
                  IS NOT NULL

                AND TRY_CONVERT(BIGINT, LTRIM(RTRIM(@p1)))
                  IS NOT NULL

                AND TRY_CONVERT(BIGINT, LTRIM(RTRIM(Member_Number)))
                  = TRY_CONVERT(BIGINT, LTRIM(RTRIM(@p1)))
              )
            ORDER BY
              CASE
                WHEN LTRIM(RTRIM(Member_Number)) = @p1
                  THEN 0
                ELSE 1
              END,
              Effective_To DESC,
              Effective_From DESC;
            `,
            [selectedMemberNumber],
          );

          if (!memberRows.length) {
            const error = new Error(
              `Member Number '${selectedMemberNumber}' was not found.`,
            );

            error.statusCode = 400;
            error.code = "MATCHED_MEMBER_NOT_FOUND";

            throw error;
          }

          const matchedMemberNumber = String(
            memberRows[0].member_number || selectedMemberNumber,
          ).trim();

          const matchedMemberName = String(
            memberRows[0].member_name || "",
          ).trim();

          const { rows: updatedRows } = await txQuery(
            `
            UPDATE dbo.Cur_Invoice_Detail
            SET
              Matched_Member_Number = @p1,
              Matched_Member_Name = @p2,
              Updated_At_UTC = GETUTCDATE()
            OUTPUT INSERTED.*
            WHERE Cur_Detail_ID = @p3
              AND Report_Number = @p4;
            `,
            [matchedMemberNumber, matchedMemberName || null, curDetailId, rn],
          );

          await txQuery(
            `
            INSERT INTO dbo.Audit_Log
            (
              Report_Number,
              Row_Key,
              Field_Name,
              Old_Value,
              New_Value,
              Changed_By,
              Change_Reason,
              Changed_At_UTC
            )
            VALUES
            (
              @p1,
              @p2,
              'matched_member_number',
              @p3,
              @p4,
              @p5,
              @p6,
              GETUTCDATE()
            );
            `,
            [
              rn,
              curDetailId,
              String(oldMatchedNumber),
              matchedMemberNumber,
              changedBy,
              reason || "Matched member selected",
            ],
          );

          await txQuery(
            `
            INSERT INTO dbo.Audit_Log
            (
              Report_Number,
              Row_Key,
              Field_Name,
              Old_Value,
              New_Value,
              Changed_By,
              Change_Reason,
              Changed_At_UTC
            )
            VALUES
            (
              @p1,
              @p2,
              'matched_member_name',
              @p3,
              @p4,
              @p5,
              @p6,
              GETUTCDATE()
            );
            `,
            [
              rn,
              curDetailId,
              String(oldMatchedName),
              matchedMemberName,
              changedBy,
              reason || "Matched member name populated automatically",
            ],
          );

          return updatedRows[0];
        }

        /*
         * Existing generic field-update logic.
         */
        const { rows: oldRows } = await txQuery(
          `
          SELECT
            CAST(${fieldName} AS NVARCHAR(MAX)) AS old_value
          FROM dbo.Cur_Invoice_Detail
          WHERE Cur_Detail_ID = @p1
            AND Report_Number = @p2;
          `,
          [curDetailId, rn],
        );

        if (!oldRows.length) {
          const error = new Error("Row not found");
          error.statusCode = 404;
          error.code = "DETAIL_ROW_NOT_FOUND";
          throw error;
        }

        const { rows: updatedRows } = await txQuery(
          `
          UPDATE dbo.Cur_Invoice_Detail
          SET
            ${fieldName} = @p1,
            Updated_At_UTC = GETUTCDATE()
          OUTPUT INSERTED.*
          WHERE Cur_Detail_ID = @p2
            AND Report_Number = @p3;
          `,
          [new_value, curDetailId, rn],
        );

        await txQuery(
          `
          INSERT INTO dbo.Audit_Log
          (
            Report_Number,
            Row_Key,
            Field_Name,
            Old_Value,
            New_Value,
            Changed_By,
            Change_Reason,
            Changed_At_UTC
          )
          VALUES
          (
            @p1,
            @p2,
            @p3,
            @p4,
            @p5,
            @p6,
            @p7,
            GETUTCDATE()
          );
          `,
          [
            rn,
            curDetailId,
            fieldName,
            oldRows[0].old_value,
            String(new_value ?? ""),
            changedBy,
            reason || "Manual correction",
          ],
        );

        return updatedRows[0];
      });

      return res.json({
        ok: true,
        row: result,
      });
    } catch (error) {
      console.error("❌ UPDATE row error:", error);

      return sendRouteError(res, next, error);
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
      if (!rn) return res.status(400).json({ error: "Invalid report number" });

      await verifyReportAccess(req, rn);
      const approver = getCurrentUserIdentifier(req);

      const approvedRows = await withTransaction(async (txQuery) => {
        const detailUpdate = await txQuery(
          `UPDATE dbo.Cur_Invoice_Detail
           SET DQ_Status='approved',
               Approved_By=@p1,
               Approved_At_UTC=GETUTCDATE(),
               Updated_At_UTC=GETUTCDATE()
           OUTPUT INSERTED.Cur_Detail_ID AS cur_detail_id,
                  DELETED.DQ_Status AS old_status
           WHERE Report_Number=@p2
             AND LOWER(COALESCE(DQ_Status, '')) IN
                 ('passed','failed','validated','new','staged');`,
          [approver, rn],
        );

        for (const row of detailUpdate.rows) {
          await txQuery(
            `INSERT INTO dbo.Audit_Log
             (Report_Number, Row_Key, Field_Name, Old_Value, New_Value,
              Changed_By, Change_Reason, Changed_At_UTC)
             VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,
                     'bulk approve',GETUTCDATE());`,
            [rn, row.cur_detail_id, row.old_status, approver],
          );
        }

        await txQuery(
          `UPDATE dbo.Cur_Invoice_Header
           SET Report_Status='approved', Approved_By=@p1,
               Approved_At_UTC=GETUTCDATE(), Updated_At_UTC=GETUTCDATE()
           WHERE Report_Number=@p2;`,
          [approver, rn],
        );

        await txQuery(
          `UPDATE dbo.Report_Number
           SET Status='approved', Updated_At_UTC=GETUTCDATE()
           WHERE Report_Number=@p1;`,
          [rn],
        );

        try {
          await txQuery(
            `INSERT INTO dbo.Users_Audit_Log
             (User_Email, Action, Context_JSON, Created_At_UTC)
             VALUES (@p1,'bulk_approve',@p2,GETUTCDATE());`,
            [approver, JSON.stringify({ report_number: rn })],
          );
        } catch (auditError) {
          console.warn("users_audit_log skipped:", auditError.message);
        }

        return detailUpdate.rows;
      });

      return res.json({
        ok: true,
        approved_rows: approvedRows.length,
        message: `${approvedRows.length} rows approved by ${approver}`,
      });
    } catch (error) {
      console.error("❌ PUT /reports/:reportNumber/approve error:", error);
      return sendRouteError(res, next, error);
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

      if (!rn) return res.status(400).json({ error: "Invalid report number" });
      if (!curDetailId)
        return res.status(400).json({ error: "Invalid detail row ID" });

      await verifyReportAccess(req, rn);
      const approver = getCurrentUserIdentifier(req);

      const updatedRow = await withTransaction(async (txQuery) => {
        const { rows: oldRows } = await txQuery(
          `SELECT DQ_Status AS dq_status
           FROM dbo.Cur_Invoice_Detail
           WHERE Report_Number=@p1 AND Cur_Detail_ID=@p2;`,
          [rn, curDetailId],
        );

        if (!oldRows.length) {
          const error = new Error("Row not found");
          error.statusCode = 404;
          error.code = "DETAIL_ROW_NOT_FOUND";
          throw error;
        }

        const oldStatus = oldRows[0].dq_status;
        const { rows: updatedRows } = await txQuery(
          `UPDATE dbo.Cur_Invoice_Detail
           SET DQ_Status='approved', Approved_By=@p3,
               Approved_At_UTC=GETUTCDATE(), Updated_At_UTC=GETUTCDATE()
           OUTPUT INSERTED.Cur_Detail_ID AS cur_detail_id,
                  INSERTED.DQ_Status AS dq_status,
                  INSERTED.Approved_By AS approved_by,
                  INSERTED.Approved_At_UTC AS approved_at_utc
           WHERE Report_Number=@p1 AND Cur_Detail_ID=@p2;`,
          [rn, curDetailId, approver],
        );

        await txQuery(
          `INSERT INTO dbo.Audit_Log
           (Report_Number, Row_Key, Field_Name, Old_Value, New_Value,
            Changed_By, Change_Reason, Changed_At_UTC)
           VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,
                   'single approve',GETUTCDATE());`,
          [rn, curDetailId, oldStatus, approver],
        );

        return updatedRows[0];
      });

      return res.json({ ok: true, row: updatedRow });
    } catch (error) {
      console.error("❌ PUT single approve error:", error);
      return sendRouteError(res, next, error);
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
    if (!rn) return res.status(400).json({ error: "Invalid report number" });
    await verifyReportAccess(req, rn);

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
    params.push(
      Math.max(0, Number(offset) || 0),
      Math.min(500, Math.max(1, Number(limit) || 50)),
    );

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
      if (!rn) return res.status(400).json({ error: "Invalid report number" });
      await verifyReportAccess(req, rn);

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
      params.push(
        Math.max(0, Number(offset) || 0),
        Math.min(500, Math.max(1, Number(limit) || 50)),
      );

      const { rows } = await query(sql, params);
      res.json({ logs: rows });
    } catch (err) {
      console.error("❌ GET /reports/:reportNumber/audit-log error:", err);
      res.status(500).json({ error: "Failed to fetch report audit log" });
    }
  },
);

/* ======================================================================
   MANUAL CREATE REPORT
   ----------------------------------------------------------------------

   PERIOD MODEL

   Report Period(s)
   - Used for reporting/search/dashboard filtering
   - Not affected by Accounting Period locks
   - Individual selected values stored in dbo.Report_Period
   - Summary stored in dbo.Report_Number.Period

   Posting Period(s)
   - Used for Accounting / NetSuite posting
   - Accounting-period lock validation applies
   - Start month stored in Report_Number.Posting_Period_Start
   - End/latest month stored in Report_Number.Posting_Period
   - End/latest month is the NetSuite Posting Period

   EXAMPLE

   Report Period:
     Start Period: 2026-01
     End Period:   2026-03

   Posting Period:
     Start Period: 2026-05
     End Period:   2026-08

   DATABASE:

     Report_Number.Period               = 2026-01 to 2026-03
     Report_Number.Posting_Period_Start = 2026-05
     Report_Number.Posting_Period       = 2026-08

     Report_Period:
       2026-01
       2026-03

   CURRENT RETURN BEHAVIOR PRESERVED
   ----------------------------------------------------------------------
   - Return must link to approved Accrual
   - Supplier inherited from Accrual
   - Contract inherited from Accrual
   - Report Period inherited from Accrual
   - Posting Period inherited from Accrual
   - Approved processed rows copied
   - Purchase and CAF dollars reversed
   - Existing scheduled IICS processing preserved

   NOTE:
   David's new Return Manual/Automatic toggle enhancement will be handled
   separately after the Period enhancement is tested.
====================================================================== */

router.post("/reports/manual-create", requireAuth, async (req, res, next) => {
  try {
    const {
      report_type,

      // ================================================================
      // NEW PERIOD MODEL
      // ================================================================

      report_periods = [],

      posting_periods = [],

      posting_period = null,

      // ================================================================
      // LEGACY PERIOD FIELDS
      // Kept temporarily for backward compatibility.
      // ================================================================

      period = null,

      periods = [],

      bp_code = null,

      contract_id = null,

      related_report_number = null,

      note = "",

      rows = [],

      validation_warnings = [],

      validation_error_details = "",
    } = req.body || {};

    /* ==================================================================
       VALIDATE REPORT TYPE
    ================================================================== */

    const allowedTypes = ["Report", "Accrual", "Adjustment", "Return"];

    if (!allowedTypes.includes(report_type)) {
      return res.status(400).json({
        error: "report_type must be Report, Accrual, Adjustment, or Return",
      });
    }

    const isReport = report_type === "Report";

    const isAccrual = report_type === "Accrual";

    const isAdjustment = report_type === "Adjustment";

    const isReturn = report_type === "Return";

    const requiresManualRows = isReport || isAccrual || isAdjustment;

    /* ==================================================================
       VALIDATE LINKED REPORT NUMBER
    ================================================================== */

    let linkedReportNumber = null;

    if (isAdjustment || isReturn) {
      linkedReportNumber = Number(related_report_number);

      if (!Number.isInteger(linkedReportNumber) || linkedReportNumber <= 0) {
        return res.status(400).json({
          error: isReturn
            ? "Linked Accrual Report # must be a positive integer"
            : "Linked Original Report # must be a positive integer",
        });
      }
    }

    /* ==================================================================
       VALIDATE MANUAL ROWS
    ================================================================== */

    if (requiresManualRows && (!Array.isArray(rows) || rows.length === 0)) {
      return res.status(400).json({
        error: `At least one detail row is required for a ${report_type}`,
      });
    }

    /* ==================================================================
       NORMALIZE REPORT PERIOD(S)

       New frontend:
         report_periods

       Legacy frontend:
         period / periods

       For Return:
         Period information is inherited from linked Accrual.
    ================================================================== */

    let submittedReportPeriods = normalizePeriods(report_periods, null);

    /*
     * Backward compatibility with previous frontend.
     */
    if (!isReturn && submittedReportPeriods.length === 0) {
      submittedReportPeriods = normalizePeriods(periods, period);
    }

    if (!isReturn && submittedReportPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one Report Period is required",
      });
    }

    const invalidReportPeriods = getInvalidAccountingPeriods(
      submittedReportPeriods,
    );

    if (!isReturn && invalidReportPeriods.length > 0) {
      return res.status(400).json({
        error: "Report Periods must use YYYY-MM format",

        code: "INVALID_REPORT_PERIOD",

        periods: invalidReportPeriods,
      });
    }

    /* ==================================================================
       NORMALIZE POSTING PERIOD(S)

       New frontend sends:

         posting_periods:
           ["2026-05", "2026-08"]

         posting_period:
           "2026-08"

       posting_period is also included to identify the ending /
       NetSuite Posting Period.
    ================================================================== */

    let submittedPostingPeriods = normalizePeriods(
      posting_periods,
      posting_period,
    );

    /*
     * Backward compatibility.
     *
     * Old frontend had only one Period concept.
     * Use ending Report Period as Posting Period if no new
     * Posting Period was supplied.
     */
    if (
      !isReturn &&
      submittedPostingPeriods.length === 0 &&
      submittedReportPeriods.length > 0
    ) {
      submittedPostingPeriods = [
        submittedReportPeriods[submittedReportPeriods.length - 1],
      ];
    }

    if (!isReturn && submittedPostingPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one Posting Period is required",
      });
    }

    const invalidPostingPeriods = getInvalidAccountingPeriods(
      submittedPostingPeriods,
    );

    if (!isReturn && invalidPostingPeriods.length > 0) {
      return res.status(400).json({
        error: "Posting Periods must use YYYY-MM format",

        code: "INVALID_POSTING_PERIOD",

        periods: invalidPostingPeriods,
      });
    }

    /* ==================================================================
       USER INFORMATION
    ================================================================== */

    const uploadedBy = req.user?.email || req.user?.username || "unknown@user";

    const uploadedByName =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploadedByType = req.user?.user_type || "internal";

    /*
     * Business Partner users must use the supplier assigned
     * to their login.
     */
    const submittedBpCode = isBpUser(req)
      ? getBpCode(req) || null
      : bp_code || null;

    /* ==================================================================
       RESOLVED VALUES

       Report / Accrual / Adjustment:
         - Use periods submitted from UI.

       Return:
         - Inherit periods from linked approved Accrual.
    ================================================================== */

    let resolvedReportPeriods = [...submittedReportPeriods];

    let resolvedPostingPeriods = [...submittedPostingPeriods];

    let resolvedPostingPeriodStart = null;

    let resolvedPostingPeriod = null;

    let resolvedBpCode = nullIfEmpty(
      typeof submittedBpCode === "string"
        ? submittedBpCode.trim()
        : submittedBpCode,
    );

    let resolvedContractId = nullIfEmpty(
      typeof contract_id === "string" ? contract_id.trim() : contract_id,
    );

    let linkedReport = null;

    let detailRowsToStage = [];

    /* ==================================================================
       VALIDATE ADJUSTMENT LINKED REPORT
    ================================================================== */

    if (isAdjustment) {
      await verifyReportAccess(req, linkedReportNumber);

      const { rows: linkedRows } = await query(
        `
        SELECT
          Report_Number AS report_number,
          Report_Type AS report_type,
          FileName AS filename,
          Period AS period,

          Posting_Period_Start
            AS posting_period_start,

          Posting_Period
            AS posting_period,

          BP_Code AS bp_code,
          Contract_ID AS contract_id,
          Status AS status

        FROM dbo.Report_Number

        WHERE Report_Number = @p1;
        `,
        [linkedReportNumber],
      );

      if (!linkedRows.length) {
        return res.status(404).json({
          error: `Linked report #${linkedReportNumber} was not found`,
        });
      }

      linkedReport = linkedRows[0];
    }

    /* ==================================================================
       LOAD RETURN SOURCE ACCRUAL

       Current Return functionality intentionally preserved.
    ================================================================== */

    if (isReturn) {
      await verifyReportAccess(req, linkedReportNumber);

      /*
       * Load linked Accrual header including new Posting Period fields.
       */
      const { rows: linkedRows } = await query(
        `
        SELECT
          Report_Number
            AS report_number,

          Report_Type
            AS report_type,

          FileName
            AS filename,

          Period
            AS period,

          Posting_Period_Start
            AS posting_period_start,

          Posting_Period
            AS posting_period,

          BP_Code
            AS bp_code,

          Contract_ID
            AS contract_id,

          Status
            AS status

        FROM dbo.Report_Number

        WHERE Report_Number = @p1;
        `,
        [linkedReportNumber],
      );

      if (!linkedRows.length) {
        return res.status(404).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` + "was not found",
        });
      }

      linkedReport = linkedRows[0];

      const linkedReportType = String(linkedReport.report_type || "")
        .trim()
        .toLowerCase();

      if (linkedReportType !== "accrual") {
        return res.status(400).json({
          error:
            `Report #${linkedReportNumber} is report type ` +
            `"${linkedReport.report_type || "Unknown"}". ` +
            "A Return must be linked to an Accrual report.",
        });
      }

      /*
       * Existing rule:
       * source Accrual must be approved.
       */
      const linkedReportStatus = String(linkedReport.status || "")
        .trim()
        .toLowerCase();

      if (linkedReportStatus !== "approved") {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} has status ` +
            `"${linkedReport.status || "Unknown"}". ` +
            "The Accrual must be approved before a Return can be created.",
        });
      }

      /* ================================================================
         RETURN SUPPLIER / CONTRACT

         Existing behavior preserved.
      ================================================================ */

      resolvedBpCode = nullIfEmpty(linkedReport.bp_code);

      resolvedContractId = nullIfEmpty(linkedReport.contract_id);

      /* ================================================================
         RETURN REPORT PERIOD(S)

         Load from Report_Period.
      ================================================================ */

      const { rows: linkedPeriodRows } = await query(
        `
        SELECT DISTINCT
          Period AS period

        FROM dbo.Report_Period

        WHERE Report_Number = @p1

          AND Period IS NOT NULL

          AND LTRIM(
                RTRIM(
                  CAST(
                    Period AS NVARCHAR(50)
                  )
                )
              ) <> ''

        ORDER BY Period;
        `,
        [linkedReportNumber],
      );

      resolvedReportPeriods = linkedPeriodRows
        .map((item) => String(item.period || "").trim())
        .filter(Boolean);

      /*
       * Backward-compatible fallback.
       */
      if (resolvedReportPeriods.length === 0 && linkedReport.period) {
        const legacyPeriod = String(linkedReport.period).trim();

        /*
         * Range:
         *   2026-01 to 2026-03
         */
        if (legacyPeriod.includes(" to ")) {
          const [startPeriod, endPeriod] = legacyPeriod
            .split(" to ")
            .map((value) => String(value || "").trim())
            .filter(Boolean);

          resolvedReportPeriods = normalizePeriods(
            [startPeriod, endPeriod],
            null,
          );
        } else {
          /*
           * Legacy comma-separated format.
           */
          resolvedReportPeriods = normalizePeriods(
            legacyPeriod
              .split(",")
              .map((value) => value.trim())
              .filter(Boolean),
            null,
          );
        }
      }

      resolvedReportPeriods = normalizePeriods(resolvedReportPeriods, null);

      if (resolvedReportPeriods.length === 0) {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` +
            "does not contain a Report Period.",
        });
      }

      /* ================================================================
         RETURN POSTING PERIOD

         New behavior only for period-storage compatibility.

         Current Return behavior still inherits period information.

         Prefer:
           linked Posting_Period_Start
           linked Posting_Period

         Fallback:
           ending Report Period
      ================================================================ */

      resolvedPostingPeriodStart = String(
        linkedReport.posting_period_start ||
          linkedReport.posting_period ||
          resolvedReportPeriods[0] ||
          "",
      ).trim();

      resolvedPostingPeriod = String(
        linkedReport.posting_period ||
          linkedReport.posting_period_start ||
          resolvedReportPeriods[resolvedReportPeriods.length - 1] ||
          "",
      ).trim();

      resolvedPostingPeriods = normalizePeriods(
        [resolvedPostingPeriodStart, resolvedPostingPeriod],
        null,
      );

      if (resolvedPostingPeriods.length === 0) {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` +
            "does not contain a Posting Period.",
        });
      }

      /* ================================================================
         COPY APPROVED PROCESSED ROWS

         Existing Return functionality preserved.
      ================================================================ */

      const { rows: sourceRows } = await query(
        `
        SELECT
          Customer_ID AS customer_id,

          Member_Number AS member_number,

          Member_Name AS member_name,

          Member_Address AS member_address,

          Member_City AS member_city,

          Member_State AS member_state,

          Member_Zip AS member_zip,

          PO AS po,

          Invoice AS invoice,

          Invoice_Date AS invoice_date,

          Ship_To AS ship_to,

          Ship_To_Address AS ship_to_address,

          Ship_To_City AS ship_to_city,

          Ship_To_State AS ship_to_state,

          Ship_To_Zip AS ship_to_zip,

          Item AS item,

          Manufacturer AS manufacturer,

          Manufacturer_Part
            AS manufacturer_part,

          UM AS um,

          Description
            AS description,

          UNSPSC AS unspsc,

          Category AS category,

          SubCategory
            AS subcategory,

          Retail_Price
            AS retail_price,

          Contract_Price
            AS contract_price,

          Qty AS qty,

          Purchase_Dollars_Calc
            AS purchase_dollars,

          CAF AS caf,

          CAF_Dollars
            AS caf_dollars

        FROM dbo.Cur_Invoice_Detail

        WHERE Report_Number = @p1

          AND LOWER(
                LTRIM(
                  RTRIM(
                    COALESCE(
                      DQ_Status,
                      ''
                    )
                  )
                )
              ) = 'approved'

        ORDER BY Cur_Detail_ID;
        `,
        [linkedReportNumber],
      );

      if (!sourceRows.length) {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` +
            "does not contain approved processed rows in " +
            "Cur_Invoice_Detail. The Accrual must be approved " +
            "before a Return can be created.",
        });
      }

      /*
       * Existing automatic reversal logic.
       */
      detailRowsToStage = sourceRows.map((sourceRow) => ({
        ...sourceRow,

        purchase_dollars: reverseAmount(sourceRow.purchase_dollars),

        caf_dollars: reverseAmount(sourceRow.caf_dollars),
      }));
    } else {
      /*
       * Existing manual-row behavior for:
       *
       * Report
       * Accrual
       * Adjustment
       */
      detailRowsToStage = rows;
    }

    /* ==================================================================
       VERIFY DETAIL ROWS
    ================================================================== */

    if (!Array.isArray(detailRowsToStage) || detailRowsToStage.length === 0) {
      return res.status(400).json({
        error: "No detail rows are available to create the report",
      });
    }

    /* ==================================================================
       FINALIZE PERIOD VALUES
    ================================================================== */

    resolvedReportPeriods = normalizePeriods(resolvedReportPeriods, null);

    resolvedPostingPeriods = normalizePeriods(resolvedPostingPeriods, null);

    /* ------------------------------------------------------------------
       Validate Report Period format.

       IMPORTANT:
       Do NOT check Report Periods against Accounting_Period locks.
    ------------------------------------------------------------------ */

    const invalidResolvedReportPeriods = getInvalidAccountingPeriods(
      resolvedReportPeriods,
    );

    if (invalidResolvedReportPeriods.length > 0) {
      return res.status(400).json({
        error: "Report Periods must use YYYY-MM format",

        code: "INVALID_REPORT_PERIOD",

        periods: invalidResolvedReportPeriods,
      });
    }

    /* ------------------------------------------------------------------
       Validate Posting Period format.
    ------------------------------------------------------------------ */

    const invalidResolvedPostingPeriods = getInvalidAccountingPeriods(
      resolvedPostingPeriods,
    );

    if (invalidResolvedPostingPeriods.length > 0) {
      return res.status(400).json({
        error: "Posting Periods must use YYYY-MM format",

        code: "INVALID_POSTING_PERIOD",

        periods: invalidResolvedPostingPeriods,
      });
    }

    /* ==================================================================
       VERIFY ONLY POSTING PERIOD(S) ARE OPEN

       This is the key new business rule.

       Report Period:
         no lock validation

       Posting Period:
         lock validation
    ================================================================== */

    try {
      await validateOpenPeriods(resolvedPostingPeriods);
    } catch (periodError) {
      return res.status(periodError.statusCode || 400).json({
        error: periodError.message,

        code: periodError.code || "POSTING_PERIOD_VALIDATION_FAILED",

        periods: periodError.periods || [],
      });
    }

    /* ==================================================================
       FINAL POSTING PERIOD START / END
    ================================================================== */

    resolvedPostingPeriodStart = resolvedPostingPeriods[0];

    resolvedPostingPeriod =
      resolvedPostingPeriods[resolvedPostingPeriods.length - 1];

    if (!resolvedPostingPeriodStart || !resolvedPostingPeriod) {
      return res.status(400).json({
        error: "Posting Period is required",
      });
    }

    /* ==================================================================
       REPORT PERIOD SUMMARY

       Single:
         2026-03

       Range:
         2026-01 to 2026-03

       Stored in Report_Number.Period.

       Individual selected values continue to be stored
       in Report_Period.
    ================================================================== */

    let periodSummary = null;

    if (resolvedReportPeriods.length === 1) {
      periodSummary = resolvedReportPeriods[0];
    } else if (resolvedReportPeriods.length > 1) {
      periodSummary = `${resolvedReportPeriods[0]} to ${
        resolvedReportPeriods[resolvedReportPeriods.length - 1]
      }`;
    }

    if (!periodSummary) {
      return res.status(400).json({
        error: "Report Period is required",
      });
    }

    /* ==================================================================
       MANUAL FILE NAME

       Existing functionality preserved.
    ================================================================== */

    const manualFileName =
      report_type === "Report"
        ? "MANUAL_REPORT"
        : report_type === "Accrual"
          ? "MANUAL_ACCRUAL"
          : report_type === "Adjustment"
            ? "MANUAL_ADJUSTMENT"
            : "MANUAL_RETURN";

    /* ==================================================================
       REPORT NOTE

       Existing functionality preserved.
    ================================================================== */

    const finalNote = isReturn
      ? [
          String(note || "").trim(),

          `Automatically reversed from Accrual Report #${linkedReportNumber}`,
        ]
          .filter(Boolean)
          .join(" - ")
      : String(note || "").trim();

    /* ==================================================================
       CREATE REPORT_NUMBER HEADER

       NEW COLUMNS:
         Posting_Period_Start
         Posting_Period
    ================================================================== */

    const reportInsertSql = `
      INSERT INTO dbo.Report_Number
      (
        FileName,

        Report_Type,

        Uploaded_By,

        Uploaded_By_Name,

        Uploaded_By_Type,

        Period,

        Posting_Period_Start,

        Posting_Period,

        BP_Code,

        Contract_ID,

        Related_Report_Number,

        Uploaded_At_UTC,

        Status,

        Note,

        Created_At_UTC,

        Updated_At_UTC
      )

      OUTPUT
        INSERTED.Report_Number
          AS report_number,

        INSERTED.Report_Type
          AS report_type,

        INSERTED.FileName
          AS filename,

        INSERTED.Period
          AS period,

        INSERTED.Posting_Period_Start
          AS posting_period_start,

        INSERTED.Posting_Period
          AS posting_period,

        INSERTED.BP_Code
          AS bp_code,

        INSERTED.Contract_ID
          AS contract_id,

        INSERTED.Related_Report_Number
          AS related_report_number,

        INSERTED.Uploaded_By
          AS uploaded_by,

        INSERTED.Uploaded_By_Name
          AS uploaded_by_name,

        INSERTED.Uploaded_By_Type
          AS uploaded_by_type,

        INSERTED.Uploaded_At_UTC
          AS uploaded_at_utc,

        INSERTED.Status
          AS status,

        INSERTED.Note
          AS note

      VALUES
      (
        @p1,
        @p2,
        @p3,
        @p4,
        @p5,

        @p6,

        @p7,

        @p8,

        @p9,

        @p10,

        @p11,

        GETUTCDATE(),

        'submitted',

        @p12,

        GETUTCDATE(),

        GETUTCDATE()
      );
    `;

    /* ==================================================================
       TRANSACTION
    ================================================================== */

    const transactionResult = await withTransaction(async (txQuery) => {
      /* ============================================================
             INSERT REPORT HEADER
          ============================================================ */

      const { rows: reportRows } = await txQuery(reportInsertSql, [
        manualFileName, // @p1
        report_type, // @p2
        uploadedBy, // @p3
        uploadedByName, // @p4
        uploadedByType, // @p5

        periodSummary, // @p6

        resolvedPostingPeriodStart, // @p7

        resolvedPostingPeriod, // @p8

        resolvedBpCode, // @p9

        resolvedContractId, // @p10

        linkedReportNumber, // @p11

        finalNote, // @p12
      ]);

      const report = reportRows?.[0];

      const reportNumber =
        report?.report_number ?? report?.Report_Number ?? null;

      if (!reportNumber) {
        throw new Error(
          "Failed to create report header: missing report number",
        );
      }

      /* ============================================================
             INSERT REPORT PERIOD(S)

             IMPORTANT:
             Only Report Period(s) go into dbo.Report_Period.

             Posting Period(s) do NOT go here.
          ============================================================ */

      for (const selectedPeriod of resolvedReportPeriods) {
        await txQuery(
          `
              INSERT INTO dbo.Report_Period
              (
                Report_Number,

                Period,

                Created_At_UTC
              )

              VALUES
              (
                @p1,

                @p2,

                GETUTCDATE()
              );
              `,
          [reportNumber, selectedPeriod],
        );
      }

      /* ============================================================
             CURATED HEADER

             Existing behavior preserved.
          ============================================================ */

      await txQuery(
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
              @p1,

              'submitted',

              @p2,

              GETUTCDATE(),

              GETUTCDATE(),

              GETUTCDATE()
            );
            `,
        [reportNumber, uploadedBy],
      );

      /* ============================================================
             STAGING ROW INSERT

             Existing functionality preserved.
          ============================================================ */

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
              @p1,
              @p2,
              @p3,
              @p4,
              @p5,
              @p6,
              @p7,
              @p8,

              @p9,
              @p10,
              @p11,

              @p12,
              @p13,
              @p14,
              @p15,
              @p16,

              @p17,
              @p18,
              @p19,
              @p20,
              @p21,
              @p22,
              @p23,
              @p24,

              @p25,
              @p26,
              @p27,
              @p28,
              @p29,
              @p30,

              GETUTCDATE()
            );
          `;

      for (const row of detailRowsToStage) {
        await txQuery(stageSql, [
          reportNumber,

          nullIfEmpty(row.customer_id),

          nullIfEmpty(row.member_number),

          nullIfEmpty(row.member_name),

          nullIfEmpty(row.member_address),

          nullIfEmpty(row.member_city),

          nullIfEmpty(row.member_state),

          nullIfEmpty(row.member_zip),

          nullIfEmpty(row.po),

          nullIfEmpty(row.invoice),

          nullIfEmpty(row.invoice_date),

          nullIfEmpty(row.ship_to),

          nullIfEmpty(row.ship_to_address),

          nullIfEmpty(row.ship_to_city),

          nullIfEmpty(row.ship_to_state),

          nullIfEmpty(row.ship_to_zip),

          nullIfEmpty(row.item),

          nullIfEmpty(row.manufacturer),

          nullIfEmpty(row.manufacturer_part),

          nullIfEmpty(row.um),

          nullIfEmpty(row.desc ?? row.description),

          nullIfEmpty(row.unspsc),

          nullIfEmpty(row.category),

          nullIfEmpty(row.subcategory),

          nullableNumber(row.retail_price),

          nullableNumber(row.contract_price),

          nullableNumber(row.qty),

          nullableNumber(row.purchase_dollars ?? row.purchase_dollars_calc),

          nullableNumber(row.caf),

          nullableNumber(row.caf_dollars),
        ]);
      }

      return {
        report,
        reportNumber,
      };
    });

    const report = transactionResult.report;

    const reportNumber = transactionResult.reportNumber;

    /* ==================================================================
       AUDIT LOG

       Audit failure does not fail report creation.
    ================================================================== */

    try {
      const auditAction = isReturn
        ? "manual_create_return"
        : isAccrual
          ? "manual_create_accrual"
          : isAdjustment
            ? "manual_create_adjustment"
            : "manual_create_report";

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

          @p2,

          @p3,

          GETUTCDATE()
        );
        `,
        [
          uploadedBy,

          auditAction,

          JSON.stringify({
            report_number: reportNumber,

            report_type,

            filename: manualFileName,

            /*
             * Keep legacy names for existing audit viewers.
             */
            period: periodSummary,

            periods: resolvedReportPeriods,

            /*
             * New explicit period fields.
             */
            report_period: periodSummary,

            report_periods: resolvedReportPeriods,

            posting_period_start: resolvedPostingPeriodStart,

            posting_period: resolvedPostingPeriod,

            posting_periods: resolvedPostingPeriods,

            bp_code: resolvedBpCode,

            contract_id: resolvedContractId,

            related_report_number: linkedReportNumber,

            source_report_type: linkedReport?.report_type || null,

            source_row_count: isReturn ? detailRowsToStage.length : null,

            row_count: detailRowsToStage.length,

            reversed_fields: isReturn
              ? ["purchase_dollars_calc", "caf_dollars"]
              : [],

            validation_warnings: isReturn ? [] : validation_warnings,

            validation_error_details: isReturn ? "" : validation_error_details,

            processing_method: "scheduled_iics_workflow",
          }),
        ],
      );
    } catch (auditError) {
      console.warn("Manual report audit log skipped:", auditError.message);
    }

    /* ==================================================================
       RESPONSE
    ================================================================== */

    const message = isReturn
      ? `Return report #${reportNumber} was created from Accrual Report #${linkedReportNumber}. ${detailRowsToStage.length} approved processed row(s) were copied and reversed. The report is ready for scheduled Informatica processing.`
      : `${report_type} report #${reportNumber} was created and staged for scheduled Informatica processing.`;

    return res.json({
      ok: true,

      report_number: reportNumber,

      report: {
        ...report,

        /*
         * Legacy response fields preserved.
         */
        period: periodSummary,

        periods: resolvedReportPeriods,

        /*
         * New fields.
         */
        report_period: periodSummary,

        report_periods: resolvedReportPeriods,

        posting_period_start: resolvedPostingPeriodStart,

        posting_period: resolvedPostingPeriod,

        posting_periods: resolvedPostingPeriods,

        bp_code: resolvedBpCode,

        contract_id: resolvedContractId,

        related_report_number: linkedReportNumber,
      },

      source_report: isReturn
        ? {
            report_number: linkedReport.report_number,

            report_type: linkedReport.report_type,

            status: linkedReport.status,

            row_count: detailRowsToStage.length,
          }
        : null,

      row_count: detailRowsToStage.length,

      status: "submitted",

      processing_method: "scheduled_iics_workflow",

      message,
    });
  } catch (error) {
    console.error("❌ POST /reports/manual-create error:", error);

    return sendRouteError(res, next, error);
  }
});

/* ======================================================================
   ACCOUNTING PERIOD STATUS
====================================================================== */

/* ======================================================================
   ACCOUNTING PERIOD STATUS
====================================================================== */

/* ======================================================================
   ACCOUNTING PERIOD MANAGEMENT

   Permissions:
   - Authenticated internal users can view periods
   - Authenticated internal users can create periods
   - Authenticated internal users can lock periods
   - Authenticated internal users can unlock periods

   Table:
   dbo.Accounting_Period

   Columns:
   - Accounting_Period_ID
   - Period
   - Is_Locked
   - Locked_By
   - Locked_At_UTC
   - Unlocked_By
   - Unlocked_At_UTC
   - Created_At_UTC
   - Updated_At_UTC
====================================================================== */

/* ======================================================================
   GET /reports/accounting-periods
====================================================================== */

router.get(
  "/reports/accounting-periods",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (_req, res, next) => {
    try {
      const { rows } = await query(`
        SELECT
          Accounting_Period_ID AS accounting_period_id,
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
      `);

      const periods = rows.map((row) => ({
        accounting_period_id: row.accounting_period_id,
        period: row.period,
        is_locked: Boolean(row.is_locked),
        status: Boolean(row.is_locked) ? "closed" : "open",
        locked_by: row.locked_by || null,
        locked_at_utc: row.locked_at_utc || null,
        unlocked_by: row.unlocked_by || null,
        unlocked_at_utc: row.unlocked_at_utc || null,
        created_at_utc: row.created_at_utc || null,
        updated_at_utc: row.updated_at_utc || null,
      }));

      return res.status(200).json({
        success: true,
        count: periods.length,
        periods,
      });
    } catch (error) {
      console.error("❌ GET /reports/accounting-periods error:", error);
      next(error);
    }
  },
);

/* ======================================================================
   POST /reports/accounting-periods
   Creates a new accounting period as Open
====================================================================== */

router.post(
  "/reports/accounting-periods",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.body?.period);

      if (!period) {
        return res.status(400).json({
          success: false,
          code: "INVALID_ACCOUNTING_PERIOD",
          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /*
       * Check whether the period already exists.
       */
      const { rows: existingRows } = await query(
        `
        SELECT
          Accounting_Period_ID AS accounting_period_id,
          Period AS period,
          Is_Locked AS is_locked
        FROM dbo.Accounting_Period
        WHERE Period = @p1;
        `,
        [period],
      );

      if (existingRows.length > 0) {
        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_EXISTS",
          message: `Accounting period ${period} already exists.`,
          period: {
            accounting_period_id: existingRows[0].accounting_period_id,
            period: existingRows[0].period,
            is_locked: Boolean(existingRows[0].is_locked),
            status: Boolean(existingRows[0].is_locked) ? "closed" : "open",
          },
        });
      }

      /*
       * Create the period as Open.
       */
      const { rows: insertedRows } = await query(
        `
        INSERT INTO dbo.Accounting_Period
        (
          Period,
          Is_Locked,
          Locked_By,
          Locked_At_UTC,
          Unlocked_By,
          Unlocked_At_UTC,
          Created_At_UTC,
          Updated_At_UTC
        )
        OUTPUT
          INSERTED.Accounting_Period_ID AS accounting_period_id,
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Locked_By AS locked_by,
          INSERTED.Locked_At_UTC AS locked_at_utc,
          INSERTED.Unlocked_By AS unlocked_by,
          INSERTED.Unlocked_At_UTC AS unlocked_at_utc,
          INSERTED.Created_At_UTC AS created_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc
        VALUES
        (
          @p1,
          0,
          NULL,
          NULL,
          NULL,
          NULL,
          GETUTCDATE(),
          GETUTCDATE()
        );
        `,
        [period],
      );

      const row = insertedRows[0];

      /*
       * Audit failure should not fail period creation.
       */
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
            'create_accounting_period',
            @p2,
            GETUTCDATE()
          );
          `,
          [
            getCurrentUserIdentifier(req),
            JSON.stringify({
              period,
              status: "open",
            }),
          ],
        );
      } catch (auditError) {
        console.warn(
          "Create accounting period audit log skipped:",
          auditError.message,
        );
      }

      return res.status(201).json({
        success: true,
        message: `Accounting period ${period} was created successfully.`,
        period: {
          accounting_period_id: row.accounting_period_id,
          period: row.period,
          is_locked: Boolean(row.is_locked),
          status: "open",
          locked_by: row.locked_by || null,
          locked_at_utc: row.locked_at_utc || null,
          unlocked_by: row.unlocked_by || null,
          unlocked_at_utc: row.unlocked_at_utc || null,
          created_at_utc: row.created_at_utc || null,
          updated_at_utc: row.updated_at_utc || null,
        },
      });
    } catch (error) {
      console.error("❌ POST /reports/accounting-periods error:", error);

      /*
       * SQL Server duplicate-key errors.
       *
       * This protects against two users creating the same month
       * at nearly the same time.
       */
      if (error?.number === 2601 || error?.number === 2627) {
        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_EXISTS",
          message: "This accounting period already exists.",
        });
      }

      next(error);
    }
  },
);

/* ======================================================================
   PUT /reports/accounting-periods/:period/lock

   CLIENT REQUIREMENT
   ----------------------------------------------------------------------
   - Lock current accounting period.
   - Require reason.
   - Preserve current Accounting_Period status fields.
   - Create permanent LOCK audit-history record.
   - Continue writing existing Users_Audit_Log record.
====================================================================== */

router.put(
  "/reports/accounting-periods/:period/lock",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.params?.period);

      const lockedBy = getCurrentUserIdentifier(req);

      const reason = String(req.body?.reason || "").trim();

      /* ================================================================
         VALIDATE PERIOD
      ================================================================ */

      if (!period) {
        return res.status(400).json({
          success: false,

          code: "INVALID_ACCOUNTING_PERIOD",

          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /* ================================================================
         VALIDATE REASON
      ================================================================ */

      if (!reason) {
        return res.status(400).json({
          success: false,

          code: "ACCOUNTING_PERIOD_REASON_REQUIRED",

          message: "A reason is required to lock an accounting period.",
        });
      }

      if (reason.length > 500) {
        return res.status(400).json({
          success: false,

          code: "ACCOUNTING_PERIOD_REASON_TOO_LONG",

          message: "Lock reason cannot exceed 500 characters.",
        });
      }

      /* ================================================================
         TRANSACTION
      ================================================================ */

      const result = await withTransaction(async (txQuery) => {
        /* ----------------------------------------------------------
               LOCK PERIOD

               Update only if currently open.
            ---------------------------------------------------------- */

        const { rows: updatedRows } = await txQuery(
          `
              UPDATE dbo.Accounting_Period

              SET
                Is_Locked = 1,

                Locked_By = @p2,

                Locked_At_UTC =
                  GETUTCDATE(),

                /*
                 * Existing behavior preserved.
                 * Clear previous unlock fields when period is locked again.
                 */
                Unlocked_By = NULL,

                Unlocked_At_UTC = NULL,

                Updated_At_UTC =
                  GETUTCDATE()

              OUTPUT
                INSERTED.Accounting_Period_ID
                  AS accounting_period_id,

                INSERTED.Period
                  AS period,

                INSERTED.Is_Locked
                  AS is_locked,

                INSERTED.Locked_By
                  AS locked_by,

                INSERTED.Locked_At_UTC
                  AS locked_at_utc,

                INSERTED.Unlocked_By
                  AS unlocked_by,

                INSERTED.Unlocked_At_UTC
                  AS unlocked_at_utc,

                INSERTED.Created_At_UTC
                  AS created_at_utc,

                INSERTED.Updated_At_UTC
                  AS updated_at_utc

              WHERE
                Period = @p1

                AND Is_Locked = 0;
              `,
          [period, lockedBy],
        );

        /* ----------------------------------------------------------
               NOT UPDATED
            ---------------------------------------------------------- */

        if (updatedRows.length === 0) {
          const { rows: existingRows } = await txQuery(
            `
                SELECT
                  Accounting_Period_ID
                    AS accounting_period_id,

                  Period
                    AS period,

                  Is_Locked
                    AS is_locked,

                  Locked_By
                    AS locked_by,

                  Locked_At_UTC
                    AS locked_at_utc

                FROM dbo.Accounting_Period

                WHERE
                  Period = @p1;
                `,
            [period],
          );

          if (existingRows.length === 0) {
            const error = new Error(
              `Accounting period ${period} is not configured.`,
            );

            error.statusCode = 404;

            error.code = "ACCOUNTING_PERIOD_NOT_FOUND";

            throw error;
          }

          const existingPeriod = existingRows[0];

          if (Boolean(existingPeriod.is_locked)) {
            const error = new Error(
              `Accounting period ${period} is already locked.`,
            );

            error.statusCode = 409;

            error.code = "ACCOUNTING_PERIOD_ALREADY_LOCKED";

            error.period = existingPeriod;

            throw error;
          }

          const error = new Error(
            `Unable to lock accounting period ${period}.`,
          );

          error.statusCode = 409;

          error.code = "ACCOUNTING_PERIOD_LOCK_FAILED";

          throw error;
        }

        const row = updatedRows[0];

        /* ==========================================================
               PERMANENT ACCOUNTING PERIOD AUDIT HISTORY
            ========================================================== */

        await txQuery(
          `
              INSERT INTO dbo.Accounting_Period_Audit
              (
                Accounting_Period_ID,

                Period,

                Action,

                Reason,

                Changed_By,

                Changed_At_UTC
              )

              VALUES
              (
                @p1,

                @p2,

                'LOCK',

                @p3,

                @p4,

                GETUTCDATE()
              );
              `,
          [row.accounting_period_id, period, reason, lockedBy],
        );

        /* ==========================================================
               EXISTING USERS AUDIT LOG
            ========================================================== */

        try {
          await txQuery(
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

                  'lock_accounting_period',

                  @p2,

                  GETUTCDATE()
                );
                `,
            [
              lockedBy,

              JSON.stringify({
                period,

                status: "closed",

                action: "LOCK",

                reason,

                locked_by: lockedBy,
              }),
            ],
          );
        } catch (auditError) {
          /*
           * Preserve your existing behavior:
           * Users_Audit_Log failure should not fail the period action.
           *
           * Accounting_Period_Audit above is the required business
           * history and is part of the transaction.
           */
          console.warn(
            "Users audit log for accounting-period lock skipped:",
            auditError.message,
          );
        }

        return row;
      });

      /* ================================================================
         RESPONSE
      ================================================================ */

      return res.status(200).json({
        success: true,

        message: `Accounting period ${period} was locked successfully.`,

        period: {
          accounting_period_id: result.accounting_period_id,

          period: result.period,

          is_locked: true,

          status: "closed",

          locked_by: result.locked_by || null,

          locked_at_utc: result.locked_at_utc || null,

          unlocked_by: result.unlocked_by || null,

          unlocked_at_utc: result.unlocked_at_utc || null,

          created_at_utc: result.created_at_utc || null,

          updated_at_utc: result.updated_at_utc || null,
        },

        audit: {
          action: "LOCK",

          reason,

          changed_by: lockedBy,
        },
      });
    } catch (error) {
      console.error(
        `❌ PUT /reports/accounting-periods/${req.params?.period}/lock error:`,
        error,
      );

      /*
       * Preserve clean HTTP errors created above.
       */
      if (error?.statusCode) {
        return res.status(error.statusCode).json({
          success: false,

          code: error.code || "ACCOUNTING_PERIOD_LOCK_FAILED",

          message: error.message,

          period: error.period
            ? {
                accounting_period_id: error.period.accounting_period_id,

                period: error.period.period,

                is_locked: Boolean(error.period.is_locked),

                status: Boolean(error.period.is_locked) ? "closed" : "open",

                locked_by: error.period.locked_by || null,

                locked_at_utc: error.period.locked_at_utc || null,
              }
            : undefined,
        });
      }

      next(error);
    }
  },
);

/* ======================================================================
   PUT /reports/accounting-periods/:period/unlock

   CLIENT REQUIREMENT
   ----------------------------------------------------------------------
   - Unlock current accounting period.
   - Require reason.
   - Preserve current Accounting_Period state.
   - Create permanent UNLOCK audit-history record.
   - Continue existing Users_Audit_Log behavior.
====================================================================== */

router.put(
  "/reports/accounting-periods/:period/unlock",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.params?.period);

      const unlockedBy = getCurrentUserIdentifier(req);

      const reason = String(req.body?.reason || "").trim();

      /* ================================================================
         VALIDATE PERIOD
      ================================================================ */

      if (!period) {
        return res.status(400).json({
          success: false,

          code: "INVALID_ACCOUNTING_PERIOD",

          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /* ================================================================
         VALIDATE REASON
      ================================================================ */

      if (!reason) {
        return res.status(400).json({
          success: false,

          code: "ACCOUNTING_PERIOD_REASON_REQUIRED",

          message: "A reason is required to unlock an accounting period.",
        });
      }

      if (reason.length > 500) {
        return res.status(400).json({
          success: false,

          code: "ACCOUNTING_PERIOD_REASON_TOO_LONG",

          message: "Unlock reason cannot exceed 500 characters.",
        });
      }

      /* ================================================================
         TRANSACTION
      ================================================================ */

      const result = await withTransaction(async (txQuery) => {
        /* ----------------------------------------------------------
               UNLOCK

               Update only if currently locked.
            ---------------------------------------------------------- */

        const { rows: updatedRows } = await txQuery(
          `
              UPDATE dbo.Accounting_Period

              SET
                Is_Locked = 0,

                Unlocked_By = @p2,

                Unlocked_At_UTC =
                  GETUTCDATE(),

                Updated_At_UTC =
                  GETUTCDATE()

              OUTPUT
                INSERTED.Accounting_Period_ID
                  AS accounting_period_id,

                INSERTED.Period
                  AS period,

                INSERTED.Is_Locked
                  AS is_locked,

                INSERTED.Locked_By
                  AS locked_by,

                INSERTED.Locked_At_UTC
                  AS locked_at_utc,

                INSERTED.Unlocked_By
                  AS unlocked_by,

                INSERTED.Unlocked_At_UTC
                  AS unlocked_at_utc,

                INSERTED.Created_At_UTC
                  AS created_at_utc,

                INSERTED.Updated_At_UTC
                  AS updated_at_utc

              WHERE
                Period = @p1

                AND Is_Locked = 1;
              `,
          [period, unlockedBy],
        );

        /* ----------------------------------------------------------
               NOT UPDATED
            ---------------------------------------------------------- */

        if (updatedRows.length === 0) {
          const { rows: existingRows } = await txQuery(
            `
                SELECT
                  Accounting_Period_ID
                    AS accounting_period_id,

                  Period
                    AS period,

                  Is_Locked
                    AS is_locked,

                  Unlocked_By
                    AS unlocked_by,

                  Unlocked_At_UTC
                    AS unlocked_at_utc

                FROM dbo.Accounting_Period

                WHERE
                  Period = @p1;
                `,
            [period],
          );

          if (existingRows.length === 0) {
            const error = new Error(
              `Accounting period ${period} is not configured.`,
            );

            error.statusCode = 404;

            error.code = "ACCOUNTING_PERIOD_NOT_FOUND";

            throw error;
          }

          const existingPeriod = existingRows[0];

          if (!Boolean(existingPeriod.is_locked)) {
            const error = new Error(
              `Accounting period ${period} is already open.`,
            );

            error.statusCode = 409;

            error.code = "ACCOUNTING_PERIOD_ALREADY_OPEN";

            error.period = existingPeriod;

            throw error;
          }

          const error = new Error(
            `Unable to unlock accounting period ${period}.`,
          );

          error.statusCode = 409;

          error.code = "ACCOUNTING_PERIOD_UNLOCK_FAILED";

          throw error;
        }

        const row = updatedRows[0];

        /* ==========================================================
               PERMANENT ACCOUNTING PERIOD AUDIT HISTORY
            ========================================================== */

        await txQuery(
          `
              INSERT INTO dbo.Accounting_Period_Audit
              (
                Accounting_Period_ID,

                Period,

                Action,

                Reason,

                Changed_By,

                Changed_At_UTC
              )

              VALUES
              (
                @p1,

                @p2,

                'UNLOCK',

                @p3,

                @p4,

                GETUTCDATE()
              );
              `,
          [row.accounting_period_id, period, reason, unlockedBy],
        );

        /* ==========================================================
               EXISTING USERS AUDIT LOG
            ========================================================== */

        try {
          await txQuery(
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

                  'unlock_accounting_period',

                  @p2,

                  GETUTCDATE()
                );
                `,
            [
              unlockedBy,

              JSON.stringify({
                period,

                status: "open",

                action: "UNLOCK",

                reason,

                unlocked_by: unlockedBy,
              }),
            ],
          );
        } catch (auditError) {
          console.warn(
            "Users audit log for accounting-period unlock skipped:",
            auditError.message,
          );
        }

        return row;
      });

      /* ================================================================
         RESPONSE
      ================================================================ */

      return res.status(200).json({
        success: true,

        message: `Accounting period ${period} was unlocked successfully.`,

        period: {
          accounting_period_id: result.accounting_period_id,

          period: result.period,

          is_locked: false,

          status: "open",

          locked_by: result.locked_by || null,

          locked_at_utc: result.locked_at_utc || null,

          unlocked_by: result.unlocked_by || null,

          unlocked_at_utc: result.unlocked_at_utc || null,

          created_at_utc: result.created_at_utc || null,

          updated_at_utc: result.updated_at_utc || null,
        },

        audit: {
          action: "UNLOCK",

          reason,

          changed_by: unlockedBy,
        },
      });
    } catch (error) {
      console.error(
        `❌ PUT /reports/accounting-periods/${req.params?.period}/unlock error:`,
        error,
      );

      if (error?.statusCode) {
        return res.status(error.statusCode).json({
          success: false,

          code: error.code || "ACCOUNTING_PERIOD_UNLOCK_FAILED",

          message: error.message,

          period: error.period
            ? {
                accounting_period_id: error.period.accounting_period_id,

                period: error.period.period,

                is_locked: Boolean(error.period.is_locked),

                status: Boolean(error.period.is_locked) ? "closed" : "open",

                unlocked_by: error.period.unlocked_by || null,

                unlocked_at_utc: error.period.unlocked_at_utc || null,
              }
            : undefined,
        });
      }

      next(error);
    }
  },
);

/* ======================================================================
   DELETE REPORT
   ----------------------------------------------------------------------
   DELETE /reports/:reportNumber

   Rules:
   - Authentication is required.
   - Only internal Admin, Accounting, or SSP Admin users can delete.
   - Business Partner users cannot delete.
   - Approved reports cannot be deleted.
   - A report cannot be deleted when another report references it through
     Related_Report_Number.
   - A deletion reason is required.
   - All report records are deleted in one SQL transaction.
   - The deletion is recorded in Users_Audit_Log.
====================================================================== */

router.delete(
  "/reports/:reportNumber",
  requireAuth,
  requireAdminOrAccountingDb,
  async (req, res, next) => {
    try {
      const reportNumber = asInt(req.params.reportNumber);

      const deletionReason = String(
        req.body?.reason ||
          req.body?.deletion_reason ||
          req.body?.delete_reason ||
          "",
      ).trim();

      /* ----------------------------------------------------------------
         Validate request
      ---------------------------------------------------------------- */

      if (!reportNumber) {
        return res.status(400).json({
          success: false,
          error: "Invalid report number",
          code: "INVALID_REPORT_NUMBER",
        });
      }

      if (!deletionReason) {
        return res.status(400).json({
          success: false,
          error: "Deletion reason is required",
          code: "DELETE_REASON_REQUIRED",
        });
      }

      if (deletionReason.length < 5) {
        return res.status(400).json({
          success: false,
          error: "Deletion reason must contain at least 5 characters",
          code: "DELETE_REASON_TOO_SHORT",
        });
      }

      if (deletionReason.length > 1000) {
        return res.status(400).json({
          success: false,
          error: "Deletion reason cannot exceed 1000 characters",
          code: "DELETE_REASON_TOO_LONG",
        });
      }

      const deletedBy = getCurrentUserIdentifier(req);

      /* ----------------------------------------------------------------
         Delete all report data in one transaction
      ---------------------------------------------------------------- */

      const result = await withTransaction(async (txQuery) => {
        /* --------------------------------------------------------------
           Lock and load the report.

           UPDLOCK and HOLDLOCK prevent the report from changing while
           the deletion transaction is running.
        -------------------------------------------------------------- */

        const { rows: reportRows } = await txQuery(
          `
          SELECT
            Report_Number AS report_number,
            FileName AS filename,
            Report_Type AS report_type,
            Period AS period,
            BP_Code AS bp_code,
            Contract_ID AS contract_id,
            Related_Report_Number AS related_report_number,
            Uploaded_By AS uploaded_by,
            Uploaded_By_Name AS uploaded_by_name,
            Uploaded_By_Type AS uploaded_by_type,
            Uploaded_At_UTC AS uploaded_at_utc,
            Status AS status,
            Note AS note
          FROM dbo.Report_Number WITH (UPDLOCK, HOLDLOCK)
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        if (!reportRows.length) {
          const error = new Error(`Report #${reportNumber} was not found.`);

          error.statusCode = 404;
          error.code = "REPORT_NOT_FOUND";

          throw error;
        }

        const report = reportRows[0];

        /* --------------------------------------------------------------
           Approved reports cannot be deleted
        -------------------------------------------------------------- */

        const normalizedStatus = String(report.status || "")
          .trim()
          .toLowerCase();

        if (normalizedStatus === "approved") {
          const error = new Error(
            `Report #${reportNumber} is approved and cannot be deleted.`,
          );

          error.statusCode = 409;
          error.code = "APPROVED_REPORT_DELETE_NOT_ALLOWED";

          throw error;
        }

        /* --------------------------------------------------------------
           Check whether another report references this report
        -------------------------------------------------------------- */

        const { rows: linkedReportRows } = await txQuery(
          `
          SELECT
            Report_Number AS report_number,
            Report_Type AS report_type,
            Status AS status
          FROM dbo.Report_Number
          WHERE Related_Report_Number = @p1
          ORDER BY Report_Number;
          `,
          [reportNumber],
        );

        if (linkedReportRows.length > 0) {
          const linkedReportNumbers = linkedReportRows
            .map((item) => item.report_number)
            .filter(Boolean);

          const error = new Error(
            `Report #${reportNumber} cannot be deleted because it is ` +
              `referenced by report(s): ${linkedReportNumbers.join(", ")}.`,
          );

          error.statusCode = 409;
          error.code = "REPORT_HAS_LINKED_REPORTS";
          error.linkedReports = linkedReportNumbers;

          throw error;
        }

        /* --------------------------------------------------------------
           Capture row counts before deleting
        -------------------------------------------------------------- */

        const { rows: countRows } = await txQuery(
          `
          SELECT
            (
              SELECT COUNT(*)
              FROM dbo.Audit_Log
              WHERE Report_Number = @p1
            ) AS audit_log_count,

            (
              SELECT COUNT(*)
              FROM dbo.Cur_Invoice_Detail
              WHERE Report_Number = @p1
            ) AS current_detail_count,

            (
              SELECT COUNT(*)
              FROM dbo.Cur_Invoice_Header
              WHERE Report_Number = @p1
            ) AS current_header_count,

            (
              SELECT COUNT(*)
              FROM dbo.Stg_Invoice_Raw
              WHERE Report_Number = @p1
            ) AS staging_row_count,

            (
              SELECT COUNT(*)
              FROM dbo.Report_Period
              WHERE Report_Number = @p1
            ) AS report_period_count;
          `,
          [reportNumber],
        );

        const deletionCounts = {
          audit_log: Number(countRows?.[0]?.audit_log_count || 0),
          current_details: Number(countRows?.[0]?.current_detail_count || 0),
          current_headers: Number(countRows?.[0]?.current_header_count || 0),
          staging_rows: Number(countRows?.[0]?.staging_row_count || 0),
          report_periods: Number(countRows?.[0]?.report_period_count || 0),
          report_number: 1,
        };

        /* --------------------------------------------------------------
           Create the permanent delete audit entry before deleting.

          * Preserve the report deletion history before removing the source data.
          *
          * Report_Delete_Audit intentionally has no foreign key to Report_Number
          * because the source report is permanently deleted.
        -------------------------------------------------------------- */

        await txQuery(
          `
  INSERT INTO dbo.Report_Delete_Audit
  (
    Report_Number,
    FileName,
    Report_Type,
    Period,
    BP_Code,
    Contract_ID,
    Related_Report_Number,

    Report_Status,
    Uploaded_By,
    Uploaded_By_Name,
    Uploaded_By_Type,
    Uploaded_At_UTC,
    Report_Note,

    Delete_Reason,
    Deleted_By_User_ID,
    Deleted_By,
    Deleted_By_Role,
    Deleted_At_UTC,

    Audit_Log_Count,
    Current_Detail_Count,
    Current_Header_Count,
    Staging_Row_Count,
    Report_Period_Count,

    Report_JSON
  )
  VALUES
  (
    @p1,
    @p2,
    @p3,
    @p4,
    @p5,
    @p6,
    @p7,

    @p8,
    @p9,
    @p10,
    @p11,
    @p12,
    @p13,

    @p14,
    @p15,
    @p16,
    @p17,
    GETUTCDATE(),

    @p18,
    @p19,
    @p20,
    @p21,
    @p22,

    @p23
  );
  `,
          [
            report.report_number,
            report.filename,
            report.report_type,
            report.period,
            report.bp_code,
            report.contract_id,
            report.related_report_number,

            report.status,
            report.uploaded_by,
            report.uploaded_by_name,
            report.uploaded_by_type,
            report.uploaded_at_utc,
            report.note,

            deletionReason,
            req.user?.user_id ?? null,
            deletedBy,
            req.user?.role ?? null,

            deletionCounts.audit_log,
            deletionCounts.current_details,
            deletionCounts.current_headers,
            deletionCounts.staging_rows,
            deletionCounts.report_periods,

            JSON.stringify({
              report_number: report.report_number,
              filename: report.filename,
              report_type: report.report_type,
              period: report.period,
              bp_code: report.bp_code,
              contract_id: report.contract_id,
              related_report_number: report.related_report_number,
              status: report.status,
              uploaded_by: report.uploaded_by,
              uploaded_by_name: report.uploaded_by_name,
              uploaded_by_type: report.uploaded_by_type,
              uploaded_at_utc: report.uploaded_at_utc,
              note: report.note,
              deletion_reason: deletionReason,
              deleted_by_user_id: req.user?.user_id ?? null,
              deleted_by: deletedBy,
              deleted_by_role: req.user?.role ?? null,
              deleted_counts: deletionCounts,
            }),
          ],
        );

        /* --------------------------------------------------------------
           Delete child data first to avoid foreign-key errors
        -------------------------------------------------------------- */

        await txQuery(
          `
          DELETE FROM dbo.Audit_Log
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        await txQuery(
          `
          DELETE FROM dbo.Cur_Invoice_Detail
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        await txQuery(
          `
          DELETE FROM dbo.Cur_Invoice_Header
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        await txQuery(
          `
          DELETE FROM dbo.Stg_Invoice_Raw
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        await txQuery(
          `
          DELETE FROM dbo.Report_Period
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        /* --------------------------------------------------------------
           Delete the parent Report_Number record last
        -------------------------------------------------------------- */

        const { rows: deletedReportRows } = await txQuery(
          `
          DELETE FROM dbo.Report_Number
          OUTPUT
            DELETED.Report_Number AS report_number,
            DELETED.FileName AS filename,
            DELETED.Report_Type AS report_type,
            DELETED.Status AS status
          WHERE Report_Number = @p1;
          `,
          [reportNumber],
        );

        if (!deletedReportRows.length) {
          const error = new Error(
            `Report #${reportNumber} could not be deleted.`,
          );

          error.statusCode = 409;
          error.code = "REPORT_DELETE_FAILED";

          throw error;
        }

        return {
          report: deletedReportRows[0],
          deleted_counts: deletionCounts,
        };
      });

      console.log(`✅ Report #${reportNumber} deleted by ${deletedBy}.`);

      return res.status(200).json({
        success: true,
        ok: true,
        report_number: reportNumber,
        deleted_report: result.report,
        deleted_counts: result.deleted_counts,
        deleted_by: deletedBy,
        deletion_reason: deletionReason,
        message: `Report #${reportNumber} was deleted successfully.`,
      });
    } catch (error) {
      console.error(
        `❌ DELETE /reports/${req.params.reportNumber} error:`,
        error,
      );

      if (error?.statusCode) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code || "REPORT_DELETE_FAILED",
          linked_reports: error.linkedReports || undefined,
        });
      }

      /*
       * SQL Server foreign-key constraint error.
       */
      if (error?.number === 547) {
        return res.status(409).json({
          success: false,
          error:
            "This report cannot be deleted because related records still " +
            "reference it.",
          code: "REPORT_DELETE_FOREIGN_KEY_CONFLICT",
        });
      }
      if (error?.number === 208) {
        return res.status(500).json({
          success: false,
          error: "Report deletion audit table was not found.",
          code: "REPORT_DELETE_AUDIT_TABLE_NOT_FOUND",
        });
      }

      if (error?.number === 207) {
        return res.status(500).json({
          success: false,
          error:
            "Report deletion audit table schema does not match the backend.",
          code: "REPORT_DELETE_AUDIT_SCHEMA_MISMATCH",
        });
      }
      return sendRouteError(res, next, error);
    }
  },
);

router.get(
  "/report-delete-audit",
  requireAuth,
  requireAdminOrAccountingDb,
  async (req, res, next) => {
    try {
      const { rows } = await query(
        `
        SELECT
            Report_Delete_Audit_ID AS report_delete_audit_id,
            Report_Number          AS report_number,
            FileName               AS filename,
            Report_Type            AS report_type,
            Report_Status          AS report_status,
            BP_Code                AS bp_code,
            Period                 AS period,
            Delete_Reason          AS delete_reason,
            Deleted_By             AS deleted_by,
            Deleted_By_Role        AS deleted_by_role,
            Deleted_At_UTC         AS deleted_at_utc
        FROM dbo.Report_Delete_Audit
        ORDER BY Deleted_At_UTC DESC;
        `,
      );

      return res.status(200).json({
        success: true,
        total: rows.length,
        logs: rows,
      });
    } catch (error) {
      console.error("❌ GET /report-delete-audit error:", error);
      return sendRouteError(res, next, error);
    }
  },
);

/* ======================================================================
   GET /reports/accounting-periods/history

   CLIENT REQUIREMENT
   ----------------------------------------------------------------------
   - Keep every lock/unlock event.
   - Show approximately the prior two years.
   - Newest events first.

   Query:
     /reports/accounting-periods/history?years=2
====================================================================== */

router.get(
  "/reports/accounting-periods/history",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      /* ================================================================
         YEARS
      ================================================================ */

      const requestedYears = Number(req.query?.years);

      const years =
        Number.isInteger(requestedYears) && requestedYears > 0
          ? Math.min(requestedYears, 10)
          : 2;

      /* ================================================================
         QUERY
      ================================================================ */

      const { rows } = await query(
        `
        SELECT
          Audit_ID
            AS audit_id,

          Accounting_Period_ID
            AS accounting_period_id,

          Period
            AS period,

          Action
            AS action,

          Reason
            AS reason,

          Changed_By
            AS changed_by,

          Changed_At_UTC
            AS changed_at_utc

        FROM dbo.Accounting_Period_Audit

        WHERE Changed_At_UTC >=
          DATEADD(
            YEAR,
            -@p1,
            GETUTCDATE()
          )

        ORDER BY
          Changed_At_UTC DESC,
          Audit_ID DESC;
        `,
        [years],
      );

      /* ================================================================
         FORMAT
      ================================================================ */

      const history = (rows || []).map((row) => ({
        audit_id: row.audit_id,

        accounting_period_id: row.accounting_period_id || null,

        period: row.period || "",

        action: String(row.action || "")
          .trim()
          .toUpperCase(),

        reason: row.reason || "",

        changed_by: row.changed_by || null,

        changed_at_utc: row.changed_at_utc || null,
      }));

      /* ================================================================
         RESPONSE
      ================================================================ */

      return res.status(200).json({
        success: true,

        years,

        count: history.length,

        history,
      });
    } catch (error) {
      console.error("❌ GET /reports/accounting-periods/history error:", error);

      next(error);
    }
  },
);

export default router;
