// server.js
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();

// ✅ Allow requests from React frontend
app.use(cors({ origin: "http://localhost:5173" }));

// ✅ Middleware
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

// ✅ Connect MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/securevault", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// ✅ Schema: store exactly what is required
const EncryptedSchema = new mongoose.Schema({
  filename: String,
  encryptedFile: String,   // ciphertext (hex)
  hash: String,            // SHA-256 digest (hex)
  encryptedAESKey: String, // RSA-OAEP encrypted AES key (hex)
  ivHex: String,           // store IV too (needed for AES-GCM decryption)
  timestamp: { type: Date, default: Date.now },
});

const EncryptedModel = mongoose.model("EncryptedData", EncryptedSchema);

// ✅ Store API
app.post("/api/store", async (req, res) => {
  try {
    const { filename, encryptedFile, hash, encryptedAESKey, ivHex } = req.body;

    const newData = new EncryptedModel({
      filename,
      encryptedFile,
      hash,
      encryptedAESKey,
      ivHex,
    });

    await newData.save();
    res.json({ success: true, message: "Data stored successfully in MongoDB" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error storing data" });
  }
});

// ✅ Retrieve by filename
app.get("/api/retrieve/:filename", async (req, res) => {
  try {
    const doc = await EncryptedModel.findOne({ filename: req.params.filename });
    if (!doc) return res.status(404).json({ success: false, message: "File not found" });

    // return only the needed fields
    res.json({
      filename: doc.filename,
      encryptedFile: doc.encryptedFile,
      hash: doc.hash,
      encryptedAESKey: doc.encryptedAESKey,
      ivHex: doc.ivHex,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Error retrieving data" });
  }
});

app.listen(5000, () => console.log("Server running on http://localhost:5000"));
