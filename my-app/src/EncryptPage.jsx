import React, { useEffect, useRef, useState } from "react";
import "./EncryptPage.css";

export default function SecureFileVault() {
  const subtle =
    typeof window !== "undefined" && window.crypto && window.crypto.subtle;
  const [file, setFile] = useState(null);
  const [pubKeyText, setPubKeyText] = useState("");
  const [privKeyText, setPrivKeyText] = useState("");
  const [filenameToRetrieve, setFilenameToRetrieve] = useState("");
  const [encrypting, setEncrypting] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [status, setStatus] = useState("");
  const [decryptedOk, setDecryptedOk] = useState(null);
  const [downloadUrl, setDownloadUrl] = useState(null);
  const [downloadName, setDownloadName] = useState("decrypted.bin");
  const fileInputRef = useRef(null);

  // Load public key from localStorage when component mounts
  useEffect(() => {
    const storedPubKey = localStorage.getItem("secureVaultPubKey");
    if (storedPubKey) setPubKeyText(storedPubKey);

    return () => {
      if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    };
  }, [downloadUrl]);

  // Save public key to localStorage whenever it changes
  useEffect(() => {
    if (pubKeyText.trim()) {
      localStorage.setItem("secureVaultPubKey", pubKeyText.trim());
    }
  }, [pubKeyText]);

  // ---------- Helpers ----------
  function bufToHex(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return Array.from(u8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexToBuf(hex) {
    const clean = hex.replace(/\s+/g, "").toLowerCase();
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++)
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out.buffer;
  }

  function pemToArrayBuffer(pem) {
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/, "")
      .replace(/-----END [^-]+-----/, "")
      .replace(/\s+/g, "");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function concatBuf(...parts) {
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
    const u1 = new Uint8Array(a);
    const u2 = new Uint8Array(b);
    if (u1.byteLength !== u2.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < u1.byteLength; i++) diff |= u1[i] ^ u2[i];
    return diff === 0;
  }

  // ---------- Crypto ----------
  async function sha256(buf) {
    return await subtle.digest("SHA-256", buf);
  }

  async function importRsaPublicKey(text) {
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
    return await subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  async function exportRawAesKey(key) {
    return await subtle.exportKey("raw", key);
  }

  async function importRawAesKey(raw) {
    return await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  async function aesGcmEncrypt(key, plaintext) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return { iv: iv.buffer, ciphertext };
  }

  async function aesGcmDecrypt(key, ivBuffer, ciphertext) {
    const iv = new Uint8Array(ivBuffer);
    return await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  }

  // ---------- Workflows ----------
  async function handleEncrypt() {
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

      // Send only encrypted file + AES key + IV (no need to send hash separately)
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
    <div className="min-h-screen w-full bg-neutral-950 text-neutral-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <section className="p-4 rounded-2xl bg-neutral-900 space-y-4">
          <textarea
            value={pubKeyText}
            onChange={(e) => setPubKeyText(e.target.value)}
            placeholder="Paste RSA PUBLIC key"
            className="w-full h-28 p-2 rounded-xl bg-neutral-800"
          />
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="w-full rounded-xl bg-neutral-800 p-2"
          />
          <button
            onClick={handleEncrypt}
            disabled={encrypting}
            className="w-full py-2 rounded-2xl bg-indigo-600 hover:bg-indigo-500"
          >
            {encrypting ? "Encrypting…" : "Encrypt & Store"}
          </button>
        </section>

        <section className="p-4 rounded-2xl bg-neutral-900 space-y-4">
          <h2 className="text-lg font-medium">2) Retrieve & Decrypt</h2>
          <textarea
            value={privKeyText}
            onChange={(e) => setPrivKeyText(e.target.value)}
            placeholder="Paste RSA PRIVATE key"
            className="w-full h-28 p-2 rounded-xl bg-neutral-800"
          />
          <input
            value={filenameToRetrieve}
            onChange={(e) => setFilenameToRetrieve(e.target.value)}
            placeholder="Enter filename to retrieve"
            className="w-full rounded-xl bg-neutral-800 p-2"
          />
          <button
            onClick={handleRetrieveAndDecrypt}
            disabled={decrypting}
            className="w-full py-2 rounded-2xl bg-green-600 hover:bg-green-500"
          >
            {decrypting ? "Decrypting…" : "Retrieve & Decrypt"}
          </button>

          {decryptedOk !== null && (
            <div className={`text-sm ${decryptedOk ? "text-emerald-400" : "text-red-400"}`}>
              {decryptedOk ? "Hash verified ✓" : "Hash mismatch ✗"}
            </div>
          )}

          {downloadUrl && (
            <a
              href={downloadUrl}
              download={downloadName}
              className="inline-block mt-2 px-3 py-2 rounded-2xl bg-neutral-800 hover:bg-neutral-700"
            >
              Download {downloadName}
            </a>
          )}
        </section>

        <div className="text-sm text-neutral-300">{status}</div>
      </div>
    </div>
  );
}
