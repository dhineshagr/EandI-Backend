import express from "express";
import nodemailer from "nodemailer";

const router = express.Router();

// ✅ Switch between Office365 and Ethereal based on .env
const useEthereal = process.env.USE_ETHEREAL === "true";

let transporter;

if (useEthereal) {
  // Ethereal test account (credentials from .env)
  transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST || "smtp.ethereal.email",
    port: process.env.MAIL_PORT || 587,
    secure: false,
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });
  console.log("📧 Using Ethereal test SMTP");
} else {
  // Office 365 / real SMTP
  transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST || "smtp.office365.com",
    port: process.env.MAIL_PORT || 587,
    secure: false,
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });
  console.log("📧 Using Office365 SMTP");
}

router.post("/", async (req, res) => {
  try {
    const { fileName, uploadedBy, errors } = req.body;

    const tableRows = errors
      .map((err) => {
        const match = err.match(/Row\s*(\d+):\s*(.*)/);
        const rowNum = match ? match[1] : "-";
        const detail = match ? match[2] : err;
        return `
          <tr>
            <td style="border:1px solid #ccc; padding:6px; text-align:center;">${rowNum}</td>
            <td style="border:1px solid #ccc; padding:6px;">${detail}</td>
          </tr>
        `;
      })
      .join("");

    const mailOptions = {
      from: `"SSP Portal" <${process.env.MAIL_USER}>`,
      to: process.env.NOTIFY_TO || "dhinesha@kashtechllc.com",
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
          <tbody>
            ${tableRows}
          </tbody>
        </table>

        <p>
          <b>Uploaded By:</b> ${uploadedBy}<br/>
          <b>File:</b> ${fileName}
        </p>

        <p>Please review these issues and take corrective action.</p>
        <p style="color:#555;">— SSP Portal Notification</p>
      `,
    };

    const info = await transporter.sendMail(mailOptions);

    // If Ethereal, give preview URL
    if (useEthereal) {
      console.log("📨 Preview URL:", nodemailer.getTestMessageUrl(info));
      return res.json({
        success: true,
        message: "Validation email sent (Ethereal test)",
        preview: nodemailer.getTestMessageUrl(info),
      });
    }

    res.json({ success: true, message: "Validation email sent to Accounting" });
  } catch (err) {
    console.error("Email send failed", err);
    res.status(500).json({ success: false, message: "Failed to send email" });
  }
});

export default router;
