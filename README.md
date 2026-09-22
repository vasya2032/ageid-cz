# ageid-cz — Zero-Data SD-JWT & OID4VP Age Assurance Sandbox

An open-source, privacy-first sandbox for age verification ready for **eIDAS 2.0**, **EUDI Wallet**, and **RFC 9901**. It runs entirely in the browser RAM with zero telemetry, zero cookies, and no database tracking.

## 🚀 Live Demo
Check out the working sandbox here: **[https://ageid.cz](https://ageid.cz)**

## ✨ Key Features
- **Zero-Data & Zero-PII**: Verify age thresholds (13+, 15+, 18+) without revealing any personal identifiable information.
- **SD-JWT Inspector**: Built-in tool to paste and inspect selective disclosures and cryptographically validate `_sd` hashes.
- **Mock Wallet & Issuer**: Simulate EUDI (European Digital Identity) issuing and Relying Party verification flows.
- **Developer-Friendly**: Includes an OID4VP Builder and ready-to-use TypeScript snippets for quick integration.

## 🛠️ Tech Stack
- **Frontend**: TypeScript, React / Vite (или укажи свой фреймворк)
- **Deployment**: Static Edge Hosting (Vercel)
- **Standards Compliance**: RFC 9901 (SD-JWT), OID4VP 1.0, EUDI STS & ARF v3.0.0

## 💻 Getting Started

### Prerequisites
Make sure you have [Node.js](https://nodejs.org) installed.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/vasya2032/ageid-cz.git
   cd ageid-cz
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

## 📄 License
This project is licensed under the **MIT License**.
