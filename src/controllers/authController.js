const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
const nodemailer = require("nodemailer");

// Create Nodemailer Transporter once at the module level
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});



/* ── POST /api/auth/signup ──────────────────────────────── */
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "All fields are required" });

    const [rows] = await db.query("SELECT id FROM admins WHERE email = ?", [email]);
    if (rows.length)
      return res.status(409).json({ success: false, message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)",
      [name, email, hash]
    );

    return res.status(201).json({
      success: true,
      message: "Account created successfully. Please log in.",
      adminId: result.insertId,
    });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/* ── POST /api/auth/login ───────────────────────────────── */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: "Email and password are required" });

    const [rows] = await db.query("SELECT * FROM admins WHERE email = ?", [email]);
    if (!rows.length)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);
    if (!match)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign(
      { id: admin.id, email: admin.email, name: admin.name },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    const { password: _pw, ...adminData } = admin;
    adminData.role = "admin";
    return res.json({ success: true, message: "Login successful", token, admin: adminData });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/* ── POST /api/auth/send-otp ──────────────────────────────── */
exports.sendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });

    // Check if admin exists
    const [rows] = await db.query("SELECT * FROM admins WHERE email = ?", [email]);
    if (!rows.length) {
      return res.status(404).json({ success: false, message: "User with this email does not exist" });
    }

    const admin = rows[0];

    // Rate Limiting Check (using last_otp_sent column)
    if (admin.last_otp_sent) {
      const lastSent = new Date(admin.last_otp_sent);
      const now = new Date();
      const diffMs = now - lastSent;
      if (diffMs < 60000) {
        const waitSec = Math.ceil((60000 - diffMs) / 1000);
        return res.status(429).json({
          success: false,
          message: `Please wait ${waitSec} seconds before requesting a new OTP.`
        });
      }
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes validity
    const now = new Date();

    // Store OTP, expiration, and last sent timestamp in database
    await db.query(
      "UPDATE admins SET reset_otp = ?, reset_otp_expires = ?, last_otp_sent = ? WHERE email = ?",
      [otp, expiresAt, now, email]
    );

    // Sign the email into a short-lived token (5 mins) - NO OTP IN PAYLOAD!
    const otpToken = jwt.sign(
      { email },
      process.env.JWT_SECRET,
      { expiresIn: "5m" }
    );

    // Send the email with the OTP code using module-level transporter
    await transporter.sendMail({
      from: `"Merit Home Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Password Reset OTP - Merit Home",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; max-width: 500px; border: 1px solid #eee; border-radius: 8px;">
          <h2 style="color: #4f46e5; text-align: center;">Reset Your Password</h2>
          <p>Please use the following One-Time Password (OTP) to reset your password. This OTP is valid for 5 minutes.</p>
          <div style="font-size: 32px; font-weight: bold; text-align: center; letter-spacing: 5px; color: #111827; padding: 15px; margin: 20px 0; background-color: #f3f4f6; border-radius: 6px;">
            ${otp}
          </div>
          <p style="font-size: 12px; color: #6b7280;">If you did not request this, you can safely ignore this email.</p>
        </div>
      `,
    });

    return res.json({ success: true, message: "OTP sent to your email", otpToken });
  } catch (err) {
    console.error("sendOtp error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/* ── POST /api/auth/verify-otp ────────────────────────────── */
exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp, otpToken } = req.body;
    if (!email || !otp || !otpToken) {
      return res.status(400).json({ success: false, message: "Email, OTP, and token are required" });
    }

    try {
      // Decode and verify the otpToken
      const decoded = jwt.verify(otpToken, process.env.JWT_SECRET);
      
      // Check if email matches
      if (decoded.email !== email) {
        return res.status(400).json({ success: false, message: "Invalid OTP token" });
      }

      // Query database for admin reset details
      const [rows] = await db.query(
        "SELECT reset_otp, reset_otp_expires FROM admins WHERE email = ?",
        [email]
      );
      if (!rows.length) {
        return res.status(404).json({ success: false, message: "User not found" });
      }

      const admin = rows[0];
      if (!admin.reset_otp || admin.reset_otp !== otp) {
        return res.status(400).json({ success: false, message: "Invalid OTP" });
      }

      const expiresAt = new Date(admin.reset_otp_expires);
      if (expiresAt < new Date()) {
        return res.status(400).json({ success: false, message: "OTP has expired. Please request a new one." });
      }

      // Clear the OTP fields so it can't be reused
      await db.query(
        "UPDATE admins SET reset_otp = NULL, reset_otp_expires = NULL WHERE email = ?",
        [email]
      );

      // Generate a temporary resetToken to allow password reset (valid for 10 mins)
      const resetToken = jwt.sign(
        { email, verified: true },
        process.env.JWT_SECRET,
        { expiresIn: "10m" }
      );

      return res.json({ success: true, message: "OTP verified successfully", resetToken });
    } catch (err) {
      return res.status(400).json({ success: false, message: "OTP has expired or is invalid. Please request a new one." });
    }
  } catch (err) {
    console.error("verifyOtp error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

/* ── POST /api/auth/reset-password-otp ────────────────────── */
exports.resetPasswordOtp = async (req, res) => {
  try {
    const { email, resetToken, newPassword } = req.body;
    if (!email || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
      // Verify resetToken
      const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
      if (decoded.email !== email || !decoded.verified) {
        return res.status(400).json({ success: false, message: "Invalid reset session" });
      }

      // Hash the new password and update in database
      const hash = await bcrypt.hash(newPassword, 10);
      await db.query("UPDATE admins SET password = ? WHERE email = ?", [hash, email]);

      return res.json({ success: true, message: "Password updated successfully" });
    } catch (err) {
      return res.status(400).json({ success: false, message: "Reset session has expired. Please start over." });
    }
  } catch (err) {
    console.error("resetPasswordOtp error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
};

