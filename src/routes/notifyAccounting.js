import express from "express";
import nodemailer from "nodemailer";

const router = express.Router();

/* ======================================================================
   📧 Office365 SMTP Transport (Centralized & Hardened)
====================================================================== */
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT || 587),
  secure: false, // STARTTLS for Office365
  requireTLS: true,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false, // Office365 cert chain handling
  },
});

transporter.verify((err) => {
  if (err) {
    console.error("❌ Email transport verification failed:", err.message);
  } else {
    console.log("📧 Email system initialized → Office365 SMTP ready");
  }
});

/* ======================================================================
   📤 SEND VALIDATION EMAIL
====================================================================== */
router.post("/", async (req, res) => {
  try {
    const { fileName, uploadedBy, errors } = req.body;

    if (!fileName || !uploadedBy) {
      return res.status(400).json({
        success: false,
        message: "fileName and uploadedBy are required",
      });
    }

    if (!Array.isArray(errors) || errors.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No validation errors provided",
      });
    }

    /* ------------------------------------------------------------
       Build HTML table rows
    ------------------------------------------------------------ */
    const tableRows = errors
      .map((err) => {
        let rowNum = "-";
        let detail = String(err);

        // Row-specific error: "Row 2: Missing value"
        const match = detail.match(/Row\s*(\d+):\s*(.*)/i);
        if (match) {
          rowNum = match[1];
          detail = match[2];
        }

        // Header-level validation errors
        else if (detail.toLowerCase().startsWith("missing required field")) {
          rowNum = "1";
        }

        return `
          <tr>
            <td style="border:1px solid #ccc; padding:6px; text-align:center;">
              ${rowNum}
            </td>
            <td style="border:1px solid #ccc; padding:6px;">
              ${detail}
            </td>
          </tr>
        `;
      })
      .join("");

    /* ------------------------------------------------------------
       Email payload
    ------------------------------------------------------------ */
    const mailOptions = {
      from: `"SSP Portal" <${process.env.MAIL_USER}>`,
      to: process.env.NOTIFY_TO || process.env.MAIL_USER,
      subject: `⚠️ SSP Upload Validation Errors – ${fileName}`,
      html: `
        <p>Hello E&I Accounting Team,</p>

        <p>The following issues were detected during a recent SSP upload:</p>

        <table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px;">
          <thead>
            <tr style="background-color:#f2f2f2;">
              <th style="border:1px solid #ccc; padding:6px; text-align:center;">Row</th>
              <th style="border:1px solid #ccc; padding:6px;">Issue</th>
            </tr>
          </thead>
          <tbody>${tableRows}</tbody>
        </table>

        <p style="margin-top:12px;">
          <b>Uploaded By:</b> ${uploadedBy}<br/>
          <b>File:</b> ${fileName}
        </p>

        <p>Please review these issues and take corrective action.</p>

        <p style="color:#555;">— SSP Portal Notification</p>
      `,
    };

    const info = await transporter.sendMail(mailOptions);

    console.log("📨 Office365 Email sent:", info.messageId);

    return res.json({
      success: true,
      message: "Validation email sent successfully",
    });
  } catch (err) {
    console.error("❌ Office365 Email failed:", err);

    return res.status(500).json({
      success: false,
      message: "Failed to send validation email",
      error: err.message,
    });
  }
});

export default router;
