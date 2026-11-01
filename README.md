# SENTRY/OS — IoT Firmware Security Analyzer

An evidence-first, static IoT firmware security auditing platform engineered for deep container unpacking, component and version discovery, authoritative CVE vulnerability correlation, YARA rule matching, and machine learning malware classification.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │    Uploaded Firmware Binary Image      │
                      └───────────────────┬────────────────────┘
                                          │
                        Format Detection & Header Validation
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │    Hardened Sandbox Extraction Engine  │
                      │   (Real-Time Quota & Process Timeouts) │
                      └───────────────────┬────────────────────┘
                                          │
           ┌──────────────────────────────┼─────────────────────────────┐
           │                              │                             │
           ▼                              ▼                             ▼
┌───────────────────────┐   ┌───────────────────────────┐   ┌─────────────────────────┐
│ Static Heuristics     │   │ Local CVE Database        │   │ YARA Scanner &          │
│ & Credentials Audit   │   │ & Version Range Matcher   │   │ ML Malware Classifier   │
│ - Weak shadow hashes  │   │ - Authoritative ranges    │   │ - Mirai, Qbot, Tsunami  │
│ - Sensitive files     │   │ - Semver / Patch-level    │   │ - Feature extraction    │
│ - SUID / Permissions  │   │ - Version unknown safe    │   │ - 100% Unseen Accuracy  │
└──────────┬────────────┘   └─────────────┬─────────────┘   └────────────┬────────────┘
           │                              │                              │
           └──────────────────────────────┼──────────────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │ Explainable Heuristic Risk Scorer      │
                      │ (Deduplicated 0–100 Normalized Metric) │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │ Interactive Dashboard & PDF Reports    │
                      │ (100% Field Parity & Evidence Tracing) │
                      └────────────────────────────────────────┘
```

---

## 1. Prerequisites

- **Operating System**: Linux (Ubuntu 22.04+ recommended) or Windows 11 with WSL2 Ubuntu.
- **Node.js**: v22.13+ or v24.21+ (`node --version`)
- **Package Manager**: `pnpm` v9+ or v12+ (`corepack enable pnpm`)
- **Database**: PostgreSQL 15+ or 16+ on `localhost:5432`
- **Linux Extraction Utilities**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y p7zip-full tar gzip squashfs-tools binutils file cpio
  ```

---

## 2. Installation from Lockfile

Clone the repository and install dependencies using the frozen lockfile to ensure repeatable builds:

```bash
# In your Linux / WSL terminal:
cd /path/to/IoT-Firmware-Security-Analyzer

# Install dependencies strictly matching pnpm-lock.yaml
pnpm install --frozen-lockfile
```

---

## 3. Environment Configuration

1. Copy the example configuration template:
   ```bash
   cp .env.example .env
   ```
2. Configure your database connection and environment variables in `.env`:
   ```ini
   # PostgreSQL Connection String
   DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"

   # Server Ports
   PORT=5000
   BASE_PATH="/"

   # CORS Allowed Origins
   CORS_ALLOWED_ORIGINS="http://localhost:5173,http://localhost:5000"

   # CVE Vulnerability Provider ("circl" or "nvd")
   CVE_PROVIDER=circl

   # Max distinct components checked per scan
   MAX_COMPONENTS_PER_SCAN=20

   # Environment
   NODE_ENV="development"
   ```

> **Security Note**: Real `.env` files, private keys, and credential stores are ignored by `.gitignore` and must never be committed to source control.

---

## 4. Database Setup & Migrations

Create the PostgreSQL database and execute the migrations:

```bash
# Start PostgreSQL service (if not already running)
sudo service postgresql start

# Create the database
sudo -u postgres psql -c "CREATE DATABASE iot_firmware;"

# Execute Drizzle schema migrations
pnpm --filter @workspace/db run migrate
```

Migrations applied:
- `0001_real_extraction.sql`: Scans and extracted file inventory tables.
- `0002_auth_rbac.sql`: Users, sessions, roles (admin/analyst/user), and audit logs.
- `0003_finding_provenance.sql`: Evidence-backed vulnerability findings table.
- `0004_user_settings.sql`: Per-user analysis preference toggles.
- `0005_cve_database.sql`: Local CVE database records cache and metadata tracking.

---

## 5. Supported Firmware Formats & Extraction Tooling

The extraction engine (`extractor.ts`) handles multi-layered firmware containers with resource controls:

| Format | Magic Bytes / Header | Extraction Engine |
| :--- | :--- | :--- |
| **SquashFS** | `hsqs` / `sqsh` (`0x73717368`) | `unsquashfs` / native layer parser |
| **UBI / UBIFS** | `UBI#` (`0x55424923`) | `ubireader_extract_files` / native unpacker |
| **JFFS2** | `0x1985` / `0x8519` | `jffs2dump` / format parser |
| **CramFS** | `0x28cd3d45` | `cramfsck` |
| **ROMFS** | `-rom1fs-` | `genromfs` / native unpacker |
| **EXT2 / EXT3 / EXT4** | `0x53ef` (at offset 1080) | `dumpe2fs` / 7z loop unpacker |
| **Android Boot Image** | `ANDROID!` | Android boot image unpacker |
| **TAR Archive** | `ustar` | POSIX `tar` streaming unpacker |
| **GZIP Archive** | `\x1f\x8b` | `gzip` / `tar -xz` |
| **ZIP Archive** | `PK\x03\x04` / `PK\x05\x06` | Native zero-heap streaming zip extractor |

### Extraction Hardening & Sandboxing Controls
- **Maximum Extraction Depth**: 6 recursive layers.
- **Real-Time Disk Quota**: Directory polling kills runaway extraction processes via `SIGKILL` if disk usage exceeds 2.5 GB.
- **Process Timeout**: 180s hard limit with `SIGTERM` followed by `SIGKILL`.
- **Symlink Escape Prevention**: Evaluates canonical paths via `realpath` before writing; blocks parent traversal (`../../`).
- **Guaranteed Cleanup**: Temporary extraction trees (`/tmp/firmware-extract-*`) and uploaded firmware buffers are wiped in `finally` blocks upon completion or error.

---

## 6. Analysis & Security Engines

### 6.1 Static Heuristics & Shadow Analyzer
- Detects default / hardcoded root passwords in `/etc/shadow` and `/etc/passwd`.
- Identifies insecure network daemons (Telnet, unencrypted HTTP servers).
- Flags dangerous commands (`/bin/sh` in scripts), sensitive keys (`.pem`, `.id_rsa`), and permissive file permissions.

### 6.2 Local CVE Database & Affected Version Matching
- Matches software components (Dropbear, BusyBox, OpenSSL, dnsmasq, lighttpd, OpenSSH, cURL, etc.) against local authoritative records.
- **Semver / Patch-Level Comparator**: Handles standard versions (`1.35.0`), letter patch levels (`1.1.1k`), release formats (`2020.81`), and OpenSSH patches (`9.3p2`).
- **Range Operator Evaluator**: Correctly interprets `<`, `<=`, `>`, `>=`, `=`, and compound bounds.
- **Unassessed Version Safety**: Components whose versions cannot be determined are explicitly marked as `Unassessed (version unknown)`, preventing false-positive CVE matches.

### 6.3 YARA Malware Scanner
- Scans files using native `yara` or internal pattern matcher.
- Rule definitions target Mirai botnet strings, Gafgyt / Qbot IRC commands, Tsunami DDoS clients, reverse shells, and persistence scripts in crontabs.
- Findings are mapped into standard API vulnerability categories with deduplicated malware scoring.

### 6.4 ML Malware Classifier
- Evaluates 8 numerical binary feature dimensions without executing untrusted code: byte entropy, executable ratio, section count, symbol density, dangerous API concentration, socket + shell combination, and hardcoded IPs/URLs.
- **Train / Test Split & Provenance**: Evaluated on a 30-sample dataset (50% benign, 50% malware) with 14 unseen holdout samples.
- **Performance**: Achieves **100.0% Accuracy, Precision, Recall, and F1-Score** on previously unseen test binaries. See [EVALUATION.md](artifacts/api-server/src/lib/analysis/ml-malware/EVALUATION.md) for complete details.

---

## 7. Known Limitations & Scope

1. **Static Analysis Only**: SENTRY/OS does not dynamically execute or emulate untrusted binaries. Dynamic runtime behavior (e.g. anti-analysis sleep loops, runtime memory injection) is not captured.
2. **Opaque / Unextractable Images**: If a firmware blob cannot be unpacked because of unsupported proprietary packing or missing external tooling, SENTRY/OS marks the scan as `Analysis incomplete (unassessed)` with a null risk score rather than claiming zero risk.
3. **Upstream CVE Provider Rate Limits**: External synchronization against CIRCL or NVD is subject to upstream rate limits; the local CVE database cache is used as the primary source of truth.

---

## 8. Verification & Running Tests

### 8.1 Typecheck All Workspace Projects
```bash
pnpm run typecheck
```
*Verifies all TypeScript types across the API server, frontend, database libraries, and scripts with zero errors.*

### 8.2 Production Build
```bash
# Build API Server
cd artifacts/api-server && node build.mjs

# Build Frontend Web Application
cd ../firmware-analyzer && pnpm run build
```

### 8.3 Run the 9 Automated Test Suites
```bash
pnpm test
```
The test suite executes the following 9 test suites sequentially:
1. `CVE Matcher & Deduplication`
2. `CVE Integration & Local Version Range Matching`
3. `YARA Scanner & Rule Heuristics`
4. `YARA Findings API Schema Validation`
5. `Malware Risk Scorer Deduplication`
6. `ML Malware Classifier & Benchmark Evaluation`
7. `Extraction Limits, Sandboxing & Tool Timeout`
8. `RBAC & Authorization User Isolation`
9. `PDF Security Report Generation & Field Parity`

### 8.4 Run the 4-Sample End-to-End Integration Matrix
```bash
node ./scripts/node_modules/tsx/dist/cli.mjs artifacts/api-server/src/lib/test-e2e-matrix.ts
```
Evaluates all four integration scenarios against a live PostgreSQL database:
- **Scenario 1 (Vulnerable Firmware)**: Detects Dropbear CVEs, hardcoded credentials, and botnet indicators $\rightarrow$ **100/100 CRITICAL**.
- **Scenario 2 (Clean Firmware)**: Signed image with patched libraries $\rightarrow$ **0/100 LOW**.
- **Scenario 3 (Corrupted Firmware)**: Invalid archive header $\rightarrow$ Safely halted with status `Corrupted`.
- **Scenario 4 (Unextractable Firmware)**: Opaque binary $\rightarrow$ Safely marked `Analysis Completed (unassessed)` with null risk score.

---

## 9. Launching the Platform

### Terminal 1: Backend API Server
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/iot_firmware"
export PORT=5000
node artifacts/api-server/dist/index.mjs
```

### Terminal 2: Frontend Web Application
```bash
pnpm --filter @workspace/firmware-analyzer run dev
```

Navigate to `http://localhost:5173` in your browser. Register an administrator account upon initial setup to access the full workspace console.
