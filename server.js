require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");

const connectDB = require("./config/db");
const User = require("./models/User");

connectDB();

const app = express();

app.use(cors());
app.use(express.json());

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

/* ---------------- EMAIL CONFIG ---------------- */

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

/* check email connection */

transporter.verify((err, success) => {
  if (err) {
    console.log("SMTP ERROR:", err);
  } else {
    console.log("SMTP SERVER READY");
  }
});

/* ---------------- SIGNUP ---------------- */

app.post(
  "/signup",
  upload.fields([
    { name: "gstFile", maxCount: 1 },
    { name: "certFile", maxCount: 1 },
  ]),
  async (req, res) => {
    try {

      console.log("BODY:", req.body);
      console.log("FILES:", req.files);

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

      const user = await User.create({
        name,
        email,
        company,
        phone,
        services,
        password: hash,
        gstFile,
        certFile,
      });

      /* SEND RESPONSE FIRST (important) */

      res.json({
        success: true,
        message: "Signup successful",
      });

      /* SEND EMAIL IN BACKGROUND */

      try {

        /* email to admin */

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_USER,
          subject: "New Vendor Signup",
          html: `
          <h3>New Vendor Registration</h3>
          Name: ${name}<br/>
          Email: ${email}<br/>
          Company: ${company}<br/>
          Phone: ${phone}<br/>
          Services: ${services}
          `,
        });

        /* email to vendor */

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Welcome to Hypernext Vendor Portal",
          html: `
          Your vendor portal account has been created successfully.
          `,
        });

      } catch (emailErr) {

        console.log("Email sending failed:", emailErr.message);

      }

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

    const user = await User.findOne({ email });

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

    console.error(err);

    res.status(500).json({ success: false });

  }
});


/* ---------------- FORGOT PASSWORD ---------------- */

app.post("/forgot-password", async (req,res)=>{

  try{

    const {email} = req.body;

    const user = await User.findOne({email});

    if(!user){
      return res.json({
        success:false,
        message:"User not found"
      });
    }

    const existing = resetOTP[email];

    if(existing && existing.expires > Date.now()){
      return res.json({
        success:true,
        message:"OTP already sent"
      });
    }

    const otp = Math.floor(100000 + Math.random()*900000).toString();

    resetOTP[email] = {
      otp,
      expires: Date.now() + 10 * 60 * 1000
    };

    console.log("OTP for",email,"=",otp);

    /* send email */

    try{

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Hypernext Password Reset OTP",
        html: `
        <h3>Password Reset</h3>
        <p>Your OTP is:</p>
        <h2>${otp}</h2>
        <p>This OTP expires in 10 minutes.</p>
        `
      });

      console.log("OTP email sent");

    }catch(emailErr){

      console.log("OTP email failed:", emailErr.message);

    }

    res.json({
      success:true,
      message:"OTP sent"
    });

  }catch(err){

    console.error("Forgot password error:",err);

    res.status(500).json({
      success:false
    });

  }

});

/* ---------------- RESET PASSWORD ---------------- */


app.post("/reset-password", async (req,res)=>{

  try{

    const {email, otp, password} = req.body;

    const record = resetOTP[email];

    if(!record){
      return res.json({
        success:false,
        message:"OTP not requested"
      });
    }

    if(record.expires < Date.now()){
      return res.json({
        success:false,
        message:"OTP expired"
      });
    }

    if(record.otp !== String(otp).trim()){
      return res.json({
        success:false,
        message:"Invalid OTP"
      });
    }

    const user = await User.findOne({email});

    if(!user){
      return res.json({
        success:false,
        message:"User not found"
      });
    }

    const hash = await bcrypt.hash(password,10);

    user.password = hash;

    await user.save();

    delete resetOTP[email];

    res.json({
      success:true,
      message:"Password updated"
    });

  }catch(err){

    console.error("Reset password error:",err);

    res.status(500).json({
      success:false
    });

  }

});

/* ---------------- START SERVER ---------------- */

app.listen(5000, () => {
  console.log("Server running on port 5000");
});