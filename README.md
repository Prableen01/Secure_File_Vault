# 🔐 Secure File Vault

A *web-based system* to securely store files with *confidentiality* and *integrity protection*, leveraging modern cryptography.  
All cryptographic operations are performed *client-side (browser)* using the *WebCrypto API, ensuring that **private keys never leave the client*.

---

## 📌 Features

- AES-256-GCM encryption for file confidentiality and integrity.
- SHA-256 hashing for integrity verification.
- RSA (asymmetric) encryption for secure key exchange.
- End-to-end security: keys are *never sent to the server*.
- Browser-based key handling:
  - Public key can be saved in *localStorage*.
  - Private key must *never be stored* – only copy-pasted when required.
- Secure storage of:
  - Encrypted file + hash
  - Encrypted AES key

---

## ⚙ Workflow

### 🔒 Encryption (Upload)
1. User selects a file.
2. A *random AES-256 key* is generated.
3. Compute *SHA-256 digest* of the file.
4. Encrypt file + hash using *AES-256-GCM*.
5. Encrypt AES key with user’s *RSA public key*.
6. Store on server:
   - Encrypted file + hash
   - Encrypted AES key  

### 🔓 Decryption (Download)
1. Retrieve encrypted file + hash + encrypted AES key from server.
2. User provides their *RSA private key* (in HEX).
3. Decrypt AES key using RSA private key.
4. Decrypt file with AES-256-GCM.
5. Verify SHA-256 digest to ensure file integrity.

---

## 🛠 Tech Stack

*Frontend (Client-Side):*
- React.js
- WebCrypto API

*Backend (Server-Side):*
- Node.js
- Storage system - MongoDB

*Crypto Libraries:*
- WebCrypto API (Browser)

---

## 🧩 System Architecture

```mermaid
flowchart LR
    User[User] --> |Selects File| Browser
    Browser --> |AES-256 Key + SHA-256 Digest| EncryptFile
    EncryptFile --> |AES-GCM Encrypted File + Digest| Server
    Browser --> |RSA Public Key| EncryptAES
    EncryptAES --> |Encrypted AES Key| Server
    Server --> |Store Encrypted File & Key| Storage

    Server --> |Retrieve Encrypted Data| Browser
    Browser --> |RSA Private Key (HEX)| DecryptAES
    DecryptAES --> |AES Key| DecryptFile
    DecryptFile --> |Verify Hash| User

🚀 Getting Started
1️⃣ Clone the Repository
git clone https://github.com/yourusername/secure-file-vault.git
cd secure-file-vault

2️⃣ Install Dependencies
# Install frontend dependencies
cd my-app
npm install

# Install backend dependencies
cd ../backend
npm install

3️⃣ Run the Application
# Start backend server
cd backend
npm run dev

# Start frontend (React)
cd ../my-app
npm start

🔑 Key Management

RSA Key Pair Generation

Use OpenSSL or an online tool:

# Generate RSA Private Key
openssl genrsa -out private.pem 2048

# Extract Public Key
openssl rsa -in private.pem -pubout -out public.pem


Convert Keys to HEX

Convert using OpenSSL or a custom script.

Paste keys into the app when prompted.

Storage

Public key: may be stored in localStorage.

Private key: must be entered manually each time (never stored).

🧪 Example Usage
🔒 Encrypt & Upload

Open the web app.

Select a file from your system.

Enter your RSA Public Key (HEX).

File is:

Hashed (SHA-256).

Encrypted (AES-256-GCM).

AES key encrypted (RSA Public Key).

Encrypted file + key uploaded to server.

🔓 Decrypt & Download

Open the app and request a file.

Paste your RSA Private Key (HEX).

AES key is decrypted.

File is decrypted and integrity checked with SHA-256.

Original file is available for download.

📂 Project Structure
secure-file-vault/
│── frontend/           # React frontend (WebCrypto API)
│   ├── src/
│   │   ├── components/ # UI Components
│   │   ├── utils/      # Cryptographic utilities
│   │   └── App.js
│   └── package.json
│
│── backend/            # Node.js / Next.js backend
│   ├── routes/         # API routes (upload/download)
│   ├── utils/          # Storage helpers
│   └── server.js
│
│── README.md

🔐 Security Considerations

✅ All cryptographic operations are client-side.

✅ AES-256-GCM provides confidentiality + integrity.

✅ RSA ensures secure key transport.

❌ Private keys should never be stored on server or client.

⚠ Always verify file hash after decryption.