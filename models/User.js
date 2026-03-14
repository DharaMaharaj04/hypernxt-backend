const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({

  name: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"]
  },

  company: {
    type: String,
    trim: true
  },

  phone: {
    type: String,
    trim: true
  },

  services: {
    type: String,
    trim: true
  },

  password: {
    type: String,
    required: true,
    select: false
  },

  gstFile: {
    type: String
  },

  certFile: {
    type: String
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

/* create index for faster login */


module.exports = mongoose.model("User", UserSchema);