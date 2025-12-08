// src/routes/auth.js
import { Router } from "express";
import { bpLogin } from "../middleware/auth.js";
import { query } from "../db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import axios from "axios";

const router = Router();
const tenantId = process.env.AZURE_TENANT_ID;
const audience = process.env.AZURE_API_AUDIENCE;
const jwtSecret = process.env.JWT_SECRET || "changeme";

const issuers = [
  `https://sts.windows.net/${tenantId}/`,
  `https://login.microsoftonline.com/${tenantId}/v2.0`,
];

const client = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/** Decode any token (BP/SQL HS256 OR Entra RS256) */
function decodeToken(token) {
  return new Promise((resolve, reject) => {
    try {
      const decoded = jwt.verify(token, jwtSecret);
      return resolve(decoded);
    } catch (err) {
      // try RS256
    }

    jwt.verify(
      token,
      getKey,
      { audience, algorithms: ["RS256"] },
      (err, decoded) => {
        if (err) return reject(err);
        if (!issuers.includes(decoded.iss)) {
          return reject(new Error("Invalid issuer"));
        }
        resolve(decoded);
      }
    );
  });
}

/** 🔹 BP login */
router.post("/bp-login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const { token, profile } = await bpLogin(username, password);
    res.json({ token, user: profile });
  } catch (err) {
    next(err);
  }
});

/** 🔹 Internal SQL user login */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const { rows } = await query(
      `SELECT user_id, username, display_name, email, role, password_hash, is_active, user_type, bp_code
       FROM users WHERE username=@p1;`,
      [username]
    );

    if (!rows.length)
      return res.status(401).json({ error: "Invalid username or password" });

    const user = rows[0];
    if (!user.is_active)
      return res.status(403).json({ error: "Account disabled" });

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid)
      return res.status(401).json({ error: "Invalid username or password" });

    const token = jwt.sign(
      {
        sub: `internal:${user.user_id}`,
        id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        user_type: user.user_type || "internal",
        bp_code: user.bp_code || null,
      },
      jwtSecret,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: {
        id: user.user_id,
        username: user.username,
        fullName: user.display_name || user.username,
        email: user.email,
        role: user.role,
        user_type: user.user_type || "internal",
        bp_code: user.bp_code || null,
      },
    });
  } catch (err) {
    console.error("❌ /auth/login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/** 🔹 Entra/MSAL login (exchange idToken → local JWT) */
router.post("/entra-login", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "Missing idToken" });

    const decoded = jwt.decode(idToken);
    if (!decoded) return res.status(401).json({ error: "Invalid idToken" });

    const email = decoded.preferred_username || decoded.upn;
    const fullName = decoded.name || email;
    const role = decoded.roles?.[0] || "internal";

    const localToken = jwt.sign(
      {
        typ: "local",
        sub: `entra:${decoded.oid}`,
        email,
        name: fullName,
        role,
        user_type: "internal",
      },
      jwtSecret,
      { expiresIn: "8h" }
    );

    res.json({
      token: localToken,
      user: {
        username: email,
        fullName,
        email,
        role,
        user_type: "internal",
      },
    });
  } catch (err) {
    console.error("❌ /auth/entra-login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/** 🔹 Azure token exchange (authorization_code or refresh_token) */
router.post("/azure/token", async (req, res) => {
  try {
    const {
      code,
      redirectUri,
      refresh_token,
      grant_type = code ? "authorization_code" : "refresh_token",
    } = req.body;

    if (!process.env.AZURE_CLIENT_ID || !process.env.AZURE_CLIENT_SECRET) {
      return res
        .status(500)
        .json({ error: "Azure app credentials missing in environment" });
    }

    const params = new URLSearchParams({
      client_id: process.env.AZURE_CLIENT_ID,
      client_secret: process.env.AZURE_CLIENT_SECRET,
      scope:
        "openid profile email offline_access api://e5614425-4dbe-4f35-b725-64b9a2b92827/.default",
      grant_type,
    });

    if (grant_type === "authorization_code") {
      if (!code || !redirectUri)
        return res.status(400).json({ error: "Missing code or redirectUri" });
      params.append("code", code);
      params.append("redirect_uri", redirectUri);
    } else if (grant_type === "refresh_token") {
      if (!refresh_token)
        return res.status(400).json({ error: "Missing refresh_token" });
      params.append("refresh_token", refresh_token);
    }

    const tenant = process.env.AZURE_TENANT_ID;
    const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;

    const response = await axios.post(tokenUrl, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    res.json(response.data);
  } catch (err) {
    console.error(
      "❌ Azure token exchange failed:",
      err.response?.data || err.message
    );
    res
      .status(err.response?.status || 500)
      .json(err.response?.data || { error: err.message });
  }
});

/** 🔹 Current logged-in user */
router.get("/me", async (req, res) => {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    const decoded = await decodeToken(token);
    res.json({ user: decoded });
  } catch (err) {
    console.error("❌ /auth/me error:", err.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

export default router;
