const mongoose = require("mongoose");

const connectDB = async () => {

  try {

    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    });

    console.log("MongoDB Connected");

  } catch (error) {

    console.error("MongoDB connection error:", error.message);
    process.exit(1);

  }

};

/* connection event listeners */

mongoose.connection.on("connected", () => {
  console.log("MongoDB connection established");
});

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected");
});

module.exports = connectDB;