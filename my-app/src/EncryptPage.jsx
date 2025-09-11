import React, { useEffect, useRef, useState } from "react";
import "./EncryptPage.css";

export default function SecureFileVault() {
  // Web Crypto API reference
  const subtle =
    typeof window !== "undefined" && window.crypto && window.crypto.subtle;

  // ---------- State ----------
  const [file, setFile] = useState(null);                   // File to be encrypted
  const [pubKeyText, setPubKeyText] = useState("");         // RSA Public Key (for encryption)
  const [privKeyText, setPrivKeyText] = useState("");       // RSA Private Key (for decryption)
  const [filenameToRetrieve, setFilenameToRetrieve] = useState(""); // Filename to fetch from server
  const [encrypting, setEncrypting] = useState(false);      // Encryption loading state
  const [decrypting, setDecrypting] = useState(false);      // Decryption loading state
  const [status, setStatus] = useState("");                 // Status messages (success/error)
  const [decryptedOk, setDecryptedOk] = useState(null);     // Whether hash check passed
  const [downloadUrl, setDownloadUrl] = useState(null);     // URL to download decrypted file
  const [downloadName, setDownloadName] = useState("decrypted.bin"); // Download filename

  const fileInputRef = useRef(null);

  // ---------- Effects ----------

  // Load stored public key from localStorage when component mounts
  useEffect(() => {
    const storedPubKey = localStorage.getItem("secureVaultPubKey");
    if (storedPubKey) setPubKeyText(storedPubKey);

    // Cleanup: revoke old object URLs to free memory
    return () => {
      if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    };
  }, [downloadUrl]);

  // Save public key in localStorage whenever it changes
  useEffect(() => {
    if (pubKeyText.trim()) {
      localStorage.setItem("secureVaultPubKey", pubKeyText.trim());
    }
  }, [pubKeyText]);

  // ---------- Helpers ----------

  function bufToHex(buf) {
    /**
     * Input: buf (ArrayBuffer or Uint8Array)
     * Output: Hexadecimal string representation
     * Purpose: Converts binary data into a human-readable hex string.
     */
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function hexToBuf(hex) {
    /**
     * Input: hex (string) - hex representation of bytes
     * Output: ArrayBuffer containing decoded bytes
     * Purpose: Converts a hex string back into binary buffer.
     */
    const clean = hex.replace(/\s+/g, "").toLowerCase();
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out.buffer;
  }

  function pemToArrayBuffer(pem) {
    /**
     * Input: pem (string) - PEM formatted key
     * Output: ArrayBuffer containing DER encoded key
     * Purpose: Converts a PEM-encoded RSA key into binary ArrayBuffer.
     */
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/, "")
      .replace(/-----END [^-]+-----/, "")
      .replace(/\s+/g, "");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function concatBuf(...parts) {
    /**
     * Input: variable number of ArrayBuffers
     * Output: Single ArrayBuffer containing concatenated data
     * Purpose: Joins multiple binary buffers into one.
     */
    const total = parts.reduce(
      (s, b) => s + (b instanceof Uint8Array ? b.byteLength : b.byteLength),
      0
    );
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      const u8 = new Uint8Array(p);
      out.set(u8, off);
      off += u8.byteLength;
    }
    return out.buffer;
  }

  function abEqual(a, b) {
    /**
     * Input: a, b (ArrayBuffers)
     * Output: boolean (true if equal, false otherwise)
     * Purpose: Securely checks equality of two buffers to prevent timing attacks.
     */
    const u1 = new Uint8Array(a);
    const u2 = new Uint8Array(b);
    if (u1.byteLength !== u2.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < u1.byteLength; i++) diff |= u1[i] ^ u2[i];
    return diff === 0;
  }

  // ---------- Crypto ----------

  async function sha256(buf) {
    /**
     * Input: buf (ArrayBuffer)
     * Output: SHA-256 hash as ArrayBuffer
     * Purpose: Generates cryptographic hash of given data.
     */
    return await subtle.digest("SHA-256", buf);
  }

  async function importRsaPublicKey(text) {
    /**
     * Input: text (string) - RSA public key in PEM or hex
     * Output: CryptoKey (usable for encryption)
     * Purpose: Converts PEM/hex RSA public key into WebCrypto CryptoKey.
     */
    const isPem = text.includes("BEGIN PUBLIC KEY");
    const der = isPem ? pemToArrayBuffer(text) : hexToBuf(text);
    return await subtle.importKey(
      "spki",
      der,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
  }

  async function importRsaPrivateKey(text) {
    /**
     * Input: text (string) - RSA private key in PEM or hex
     * Output: CryptoKey (usable for decryption)
     * Purpose: Converts PEM/hex RSA private key into WebCrypto CryptoKey.
     */
    if (text.includes("BEGIN RSA PRIVATE KEY")) {
      throw new Error(
        "PKCS#1 private key not supported. Convert to PKCS#8 using OpenSSL."
      );
    }
    const isPem = text.includes("BEGIN PRIVATE KEY");
    const der = isPem ? pemToArrayBuffer(text) : hexToBuf(text);
    return await subtle.importKey(
      "pkcs8",
      der,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  }

  async function generateAesGcmKey() {
    /**
     * Input: None
     * Output: CryptoKey (AES-GCM key)
     * Purpose: Creates a random AES-256 key for file encryption.
     */
    return await subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  async function exportRawAesKey(key) {
    /**
     * Input: key (CryptoKey - AES key)
     * Output: ArrayBuffer containing raw key bytes
     * Purpose: Converts CryptoKey into raw byte format.
     */
    return await subtle.exportKey("raw", key);
  }

  async function importRawAesKey(raw) {
    /**
     * Input: raw (ArrayBuffer - AES key bytes)
     * Output: CryptoKey (AES key)
     * Purpose: Converts raw AES key bytes back into CryptoKey.
     */
    return await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  async function aesGcmEncrypt(key, plaintext) {
    /**
     * Input: key (CryptoKey), plaintext (ArrayBuffer)
     * Output: Object { iv: ArrayBuffer, ciphertext: ArrayBuffer }
     * Purpose: Encrypts plaintext using AES-GCM with random IV.
     */
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return { iv: iv.buffer, ciphertext };
  }

  async function aesGcmDecrypt(key, ivBuffer, ciphertext) {
    /**
     * Input: key (CryptoKey), ivBuffer (ArrayBuffer), ciphertext (ArrayBuffer)
     * Output: ArrayBuffer (decrypted plaintext)
     * Purpose: Decrypts AES-GCM encrypted data using provided key and IV.
     */
    const iv = new Uint8Array(ivBuffer);
    return await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  }

  // ---------- Workflows ----------

  async function handleEncrypt() {
    /**
     * Input: Reads selected file + RSA public key from state
     * Output: Sends encrypted file + AES key (RSA wrapped) to server
     * Purpose: Full encryption pipeline before storage.
     */
    try {
      setStatus("");
      setEncrypting(true);
      setDecryptedOk(null);

      if (!file) throw new Error("Select a file first");
      if (!pubKeyText.trim()) throw new Error("Paste RSA PUBLIC key");

      const pubKey = await importRsaPublicKey(pubKeyText.trim());
      const fileBuf = await file.arrayBuffer();
      const digest = await sha256(fileBuf);
      const payload = concatBuf(digest, fileBuf);

      const aesKey = await generateAesGcmKey();
      const { iv, ciphertext } = await aesGcmEncrypt(aesKey, payload);

      const rawAes = await exportRawAesKey(aesKey);
      const rsaEncAes = await subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawAes);

      await fetch("http://localhost:5000/api/store", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          encryptedFile: bufToHex(ciphertext),
          encryptedAESKey: bufToHex(rsaEncAes),
          ivHex: bufToHex(iv),
        }),
      });

      setStatus("Encrypted ✅ — Stored on server");
    } catch (err) {
      setStatus(`Encrypt error: ${err.message}`);
    } finally {
      setEncrypting(false);
    }
  }

  async function handleRetrieveAndDecrypt() {
    /**
     * Input: Reads filename + RSA private key from state
     * Output: Decrypts file, verifies hash, prepares for download
     * Purpose: Full retrieval + decryption pipeline.
     */
    try {
      setStatus("");
      setDecrypting(true);
      setDecryptedOk(null);

      if (!privKeyText.trim()) throw new Error("Paste RSA PRIVATE key");
      if (!filenameToRetrieve.trim()) throw new Error("Enter filename to retrieve");

      const res = await fetch(
        `http://localhost:5000/api/retrieve/${filenameToRetrieve.trim()}`
      );
      if (!res.ok) throw new Error("File not found on server");
      const data = await res.json();

      const iv = hexToBuf(data.ivHex);
      const rsaEncAes = hexToBuf(data.encryptedAESKey);
      const ciphertext = hexToBuf(data.encryptedFile);

      const privKey = await importRsaPrivateKey(privKeyText.trim());
      const rawAes = await subtle.decrypt({ name: "RSA-OAEP" }, privKey, rsaEncAes);
      const aesKey = await importRawAesKey(rawAes);

      const decrypted = await aesGcmDecrypt(aesKey, iv, ciphertext);
      const decU8 = new Uint8Array(decrypted);

      const hashPart = decU8.slice(0, 32).buffer;
      const filePart = decU8.slice(32).buffer;

      const recomputed = await sha256(filePart);
      const ok = abEqual(hashPart, recomputed);
      setDecryptedOk(ok);

      const name = `DECRYPTED_${data.filename}`;
      setDownloadName(name);
      const blob = new Blob([filePart], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      if (downloadUrl) URL.revokeObjectURL(downloadUrl);
      setDownloadUrl(url);

      setStatus(ok ? "Decrypted ✅ — Hash verified" : "Decrypted ⚠️ — Hash mismatch");
    } catch (err) {
      setStatus(`Decrypt error: ${err.message}`);
    } finally {
      setDecrypting(false);
    }
  }

  // ---------- UI ----------
  
  return (
    <div className="vault-container">
      <h1>🔒 Secure File Vault</h1>

      <div className="vault-grid">
        {/* Encrypt Section */}
        <section className="vault-card">
          <h2>1) Encrypt & Store</h2>
          <textarea
            value={pubKeyText}
            onChange={(e) => setPubKeyText(e.target.value)}
            placeholder="Paste RSA PUBLIC key"
          />
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          <button onClick={handleEncrypt} disabled={encrypting}>
            {encrypting ? "Encrypting…" : "Encrypt & Store"}
          </button>
        </section>

        {/* Decrypt Section */}
        <section className="vault-card">
          <h2>2) Retrieve & Decrypt</h2>
          <textarea
            value={privKeyText}
            onChange={(e) => setPrivKeyText(e.target.value)}
            placeholder="Paste RSA PRIVATE key"
          />
          <input
            type="text"
            value={filenameToRetrieve}
            onChange={(e) => setFilenameToRetrieve(e.target.value)}
            placeholder="Enter filename to retrieve"
          />
          <button onClick={handleRetrieveAndDecrypt} disabled={decrypting}>
            {decrypting ? "Decrypting…" : "Retrieve & Decrypt"}
          </button>

          {/* Show hash verification result */}
          {decryptedOk !== null && (
            <div className={`status ${decryptedOk ? "success" : "error"}`}>
              {decryptedOk ? "Hash verified ✓" : "Hash mismatch ✗"}
            </div>
          )}

          {/* Download link for decrypted file */}
          {downloadUrl && (
            <a href={downloadUrl} download={downloadName}>
              Download {downloadName}
            </a>
          )}
        </section>
      </div>

      {/* Global status message */}
      <div className="status">{status}</div>
    </div>
  );
}
