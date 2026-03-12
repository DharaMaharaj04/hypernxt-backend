const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({

  name: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  company: {
    type: String
  },

  phone: {
    type: String
  },

  services: {
    type: String
  },

  password: {
    type: String,
    required: true
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

module.exports = mongoose.model("User", UserSchema);