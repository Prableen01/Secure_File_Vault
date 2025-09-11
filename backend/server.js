const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();

/* Middleware */

// Enable CORS only for frontend (React on Vite at port 5173)
app.use(cors({ origin: "http://localhost:5173" }));

// Parse incoming JSON + URL-encoded bodies 
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

/* Database Connection */
mongoose.connect("mongodb://127.0.0.1:27017/securevault", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

/* Schema + Model */
const EncryptedSchema = new mongoose.Schema({
  /**
 * EncryptedSchema
 * Fields:
 *   - filename        : (String) Unique identifier for the file
 *   - encryptedFile   : (String, hex) AES-encrypted file contents
 *   - encryptedAESKey : (String, hex) RSA-OAEP encrypted AES session key
 *   - ivHex           : (String, hex) Initialization vector used in AES-GCM
 *   - timestamp       : (Date) Record creation time (default: now)
 */
  filename: String,
  encryptedFile: String,
  encryptedAESKey: String,
  ivHex: String,
  timestamp: { type: Date, default: Date.now },
});

const EncryptedModel = mongoose.model("EncryptedData", EncryptedSchema);

/* API Routes*/

app.post("/api/store", async (req, res) => {

  /**
 * route   POST /api/store
 * desc    Store an encrypted file + metadata in MongoDB
 * input   req.body = {
 *             filename: String,
 *             encryptedFile: String (hex),
 *             encryptedAESKey: String (hex),
 *             ivHex: String (hex)
 *          }
 * output  JSON response:
 *          { success: true/false, message: String }
 */

  try {
    const { filename, encryptedFile, encryptedAESKey, ivHex } = req.body;

    // Validate required fields
    if (!filename || !encryptedFile || !encryptedAESKey || !ivHex) {
      return res
        .status(400)
        .json({ success: false, message: "Missing required fields" });
    }

    // Save to MongoDB
    const newData = new EncryptedModel({
      filename,
      encryptedFile,
      encryptedAESKey,
      ivHex,
    });

    await newData.save();

    res.json({ success: true, message: "Data stored successfully in MongoDB" });
  } catch (err) {
    console.error("Error storing data:", err);
    res.status(500).json({ success: false, message: "Error storing data" });
  }
});


app.get("/api/retrieve/:filename", async (req, res) => {

  /**
 * route   GET /api/retrieve/:filename
 * desc    Retrieve an encrypted file by filename
 * input   req.params.filename → String (filename identifier)
 * output  JSON response:
 *          {
 *             filename: String,
 *             encryptedFile: String,
 *             encryptedAESKey: String,
 *             ivHex: String
 *          }
 *          OR error message if not found
 */

  try {
    const doc = await EncryptedModel.findOne({ filename: req.params.filename });

    if (!doc) {
      return res
        .status(404)
        .json({ success: false, message: "File not found" });
    }

    res.json({
      filename: doc.filename,
      encryptedFile: doc.encryptedFile,
      encryptedAESKey: doc.encryptedAESKey,
      ivHex: doc.ivHex,
    });
  } catch (err) {
    console.error("Error retrieving data:", err);
    res.status(500).json({ success: false, message: "Error retrieving data" });
  }
});

/* Server Init */
// Start Express server on port 5000
app.listen(5000, () =>
  console.log("✅ Server running on http://localhost:5000")
);
