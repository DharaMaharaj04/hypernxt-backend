require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const { Resend } = require("resend");

const connectDB = require("./config/db");
const User = require("./models/User");

connectDB();

const app = express();

app.use(cors());
app.use(express.json());

/* ---------------- RESEND EMAIL ---------------- */

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: "Hypernext <1scriptics@gmail.com>",
      to,
      subject,
      html
    });

    console.log("Email sent to:", to);

  } catch (err) {
    console.error("Email error:", err);
  }
}

/* ---------------- TEST ROUTE ---------------- */

app.get("/", (req, res) => {
  res.send("API running");
});

/* ---------------- FILE UPLOAD ---------------- */

if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

/* ---------------- OTP MEMORY ---------------- */

let resetOTP = {};

/* ---------------- SIGNUP ---------------- */

app.post(
  "/signup",
  upload.fields([
    { name: "gstFile", maxCount: 1 },
    { name: "certFile", maxCount: 1 },
  ]),
  async (req, res) => {
    try {

      const { name, email, company, phone, services, password } = req.body;

      if (!name || !email || !password) {
        return res.json({
          success: false,
          message: "Missing required fields",
        });
      }

      const gstFile =
        req.files && req.files.gstFile
          ? req.files.gstFile[0].filename
          : null;

      const certFile =
        req.files && req.files.certFile
          ? req.files.certFile[0].filename
          : null;

      const exists = await User.findOne({ email });

      if (exists) {
        return res.json({
          success: false,
          message: "User already exists",
        });
      }

      const hash = await bcrypt.hash(password, 10);

      await User.create({
        name,
        email,
        company,
        phone,
        services,
        password: hash,
        gstFile,
        certFile,
      });

      /* send response first */

      res.json({
        success: true,
        message: "Signup successful",
      });

      /* send emails in background */

      sendEmail(
        process.env.EMAIL_USER,
        "New Vendor Signup",
        `
        <h3>New Vendor Registration</h3>
        Name: ${name}<br/>
        Email: ${email}<br/>
        Company: ${company}<br/>
        Phone: ${phone}<br/>
        Services: ${services}
        `
      );

      sendEmail(
        email,
        "Welcome to Hypernext Vendor Portal",
        `
        Your vendor portal account has been created successfully.
        `
      );

    } catch (err) {

      console.error("Signup error:", err);

      res.status(500).json({
        success: false,
        message: "Server error",
      });

    }
  }
);

/* ---------------- LOGIN ---------------- */

app.post("/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.json({ success: false });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.json({ success: false });
    }

    const token = jwt.sign(
      { email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      success: true,
      token,
    });

  } catch (err) {

    console.error("Login error:", err);

    res.status(500).json({
      success: false,
      message: "Server error",
    });

  }

});

/* ---------------- FORGOT PASSWORD ---------------- */

app.post("/forgot-password", async (req, res) => {

  try {

    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    const existing = resetOTP[email];

    if (existing && existing.expires > Date.now()) {
      return res.json({
        success: true,
        message: "OTP already sent",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    resetOTP[email] = {
      otp,
      expires: Date.now() + 10 * 60 * 1000,
    };

    console.log("OTP for", email, "=", otp);

    sendEmail(
      email,
      "Hypernext Password Reset OTP",
      `
      <h3>Password Reset</h3>
      <p>Your OTP is:</p>
      <h2>${otp}</h2>
      <p>This OTP expires in 10 minutes.</p>
      `
    );

    res.json({
      success: true,
      message: "OTP sent",
    });

  } catch (err) {

    console.error("Forgot password error:", err);

    res.status(500).json({
      success: false,
    });

  }

});

/* ---------------- RESET PASSWORD ---------------- */

app.post("/reset-password", async (req, res) => {

  try {

    const { email, otp, password } = req.body;

    const record = resetOTP[email];

    if (!record) {
      return res.json({
        success: false,
        message: "OTP not requested",
      });
    }

    if (record.expires < Date.now()) {
      return res.json({
        success: false,
        message: "OTP expired",
      });
    }

    if (record.otp !== String(otp).trim()) {
      return res.json({
        success: false,
        message: "Invalid OTP",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    const hash = await bcrypt.hash(password, 10);

    user.password = hash;

    await user.save();

    delete resetOTP[email];

    res.json({
      success: true,
      message: "Password updated",
    });

  } catch (err) {

    console.error("Reset password error:", err);

    res.status(500).json({
      success: false,
    });

  }

});

/* ---------------- START SERVER ---------------- */

app.listen(5000, () => {
  console.log("Server running on port 5000");
});