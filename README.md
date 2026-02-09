# 🔍 EOL Scanner

> **Scan container images for end-of-life (EOL) components before they become security risks!**

EOL Scanner analyzes container images to identify software components that have reached or are approaching their end-of-life status. It generates an SBOM (Software Bill of Materials) and cross-references detected packages against the [endoflife.date](https://endoflife.date) database.

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [CLI Reference](#-cli-reference)
- [Architecture](#-architecture)
- [Code Structure](#-code-structure)
- [How It Works](#-how-it-works)
- [Database Schema](#-database-schema)
- [Building from Source](#-building-from-source)
- [Configuration](#-configuration)
- [Examples](#-examples)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🐳 **Multi-Source Support** | Scan from Docker daemon, container registries, or tar archives |
| 🖥️ **OS Detection** | Automatically detects and checks Linux distribution EOL status |
| 📦 **Package Matching** | Matches packages via PURL, CPE, and name-based lookups |
| 📅 **Forward Looking** | Configure days ahead to warn about upcoming EOL dates |
| 🔄 **Auto-Sync Database** | Automatically keeps EOL data fresh from endoflife.date API |
| 📊 **Multiple Output Formats** | Table view for humans, JSON for automation |
| 🔐 **Private Registry Support** | Authenticate via username/password, token, or mTLS |
| ⚡ **Fast & Offline** | Local SQLite database for quick offline lookups |

---

## 🚀 Quick Start

```bash
# Build the scanner
go build -o eol-scanner .

# Sync the EOL database (first time)
./eol-scanner db sync

# Scan a Docker image
./eol-scanner scan nginx:latest

# Scan with 180-day forward lookup
./eol-scanner scan --days 180 python:3.9
```

---

## 📥 Installation

### Prerequisites

- **Go 1.21+** (for building from source)
- **Docker** (optional, for scanning local Docker images)

### From Source

```bash
git clone https://github.com/j0356/eol-scanner.git
cd eol-scanner
go build -o eol-scanner .
```

### With Version Information

```bash
go build -ldflags "-X github.com/j0356/eol-scanner/cmd.Version=1.0.0 \
                   -X github.com/j0356/eol-scanner/cmd.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
                   -X github.com/j0356/eol-scanner/cmd.GitCommit=$(git rev-parse --short HEAD)" \
         -o eol-scanner .
```

---

## 📖 Usage

### Basic Scanning

```bash
# Scan a local Docker image
eol-scanner scan nginx:latest

# Scan from a container registry
eol-scanner scan --source registry ghcr.io/org/myapp:v1.2.3

# Scan a tar archive
eol-scanner scan --source tar ./image.tar
```

### Output Formats

```bash
# Human-readable table (default)
eol-scanner scan alpine:latest

# JSON output for CI/CD pipelines
eol-scanner scan --output json python:3.9

# Show only EOL and EOL-soon components
eol-scanner scan --only-eol ubuntu:20.04
```

### Forward Lookup

```bash
# Check for EOL within next 30 days
eol-scanner scan --days 30 node:18

# Check for EOL within next 180 days
eol-scanner scan --days 180 debian:bullseye
```

### Database Management

```bash
# Sync with latest EOL data
eol-scanner db sync

# Sync specific categories only
eol-scanner db sync --categories lang,framework,database

# View database statistics
eol-scanner db stats

# Show database file path
eol-scanner db path
```

### Private Registries

```bash
# Basic auth (username/password)
eol-scanner scan --source registry \
    --registry-user myuser \
    --registry-pass mytoken \
    my-registry.example.com/app:latest

# Token-based auth (e.g., GitHub Container Registry)
eol-scanner scan --source registry \
    --registry-token ghp_xxxxxxxxxxxx \
    ghcr.io/org/image:tag

# mTLS authentication
eol-scanner scan --source registry \
    --registry-cert /path/to/client.crt \
    --registry-key /path/to/client.key \
    my-registry.example.com/app:latest

# mTLS with custom CA certificate
eol-scanner scan --source registry \
    --registry-cert /path/to/client.crt \
    --registry-key /path/to/client.key \
    --registry-ca /path/to/ca.crt \
    my-registry.example.com/app:latest
```

---

## 📚 CLI Reference

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--db` | | Custom database path | `~/eol-db/eol.db` |
| `--verbose` | `-v` | Enable verbose output | `false` |

### `scan` Command

Scan a container image for EOL components.

```bash
eol-scanner scan [flags] <image>
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--source` | `-s` | Image source: `docker`, `registry`, `tar` | `docker` |
| `--days` | `-d` | Forward lookup days for upcoming EOL | `90` |
| `--output` | `-o` | Output format: `table`, `json` | `table` |
| `--only-eol` | | Only show EOL and EOL-soon components | `false` |
| `--no-update` | | Skip automatic database update | `false` |
| `--registry-user` | | Registry username for authentication | |
| `--registry-pass` | | Registry password for authentication | |
| `--registry-token` | | Registry token for token-based authentication | |
| `--registry-cert` | | Client certificate path for mTLS authentication | |
| `--registry-key` | | Client key path for mTLS authentication | |
| `--registry-ca` | | Custom CA certificate file or directory | |

### `db` Command

Manage the EOL database.

#### `db sync`

Synchronize the local database with endoflife.date.

```bash
eol-scanner db sync [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--categories` | Categories to sync (comma-separated) | `framework,lang,os,database,server-app` |

#### `db stats`

Display database statistics.

```bash
eol-scanner db stats
```

#### `db path`

Show the database file path.

```bash
eol-scanner db path
```

### `version` Command

Display version information.

```bash
eol-scanner version
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          EOL Scanner                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   CLI       │───▶│  Scanner    │───▶│  EOL Database      │  │
│  │  (Cobra)    │    │   Engine    │    │   Manager           │  │
│  └─────────────┘    └──────┬──────┘    └──────────┬──────────┘  │
│                            │                      │             │
│                            ▼                      ▼             │
│                    ┌─────────────┐         ┌─────────────┐      │
│                    │    SBOM     │         │   SQLite    │      │
│                    │  Generator  │         │   Database  │      │
│                    │   (Syft)    │         │  (eol.db)   │      │
│                    └──────┬──────┘         └──────┬──────┘      │
│                           │                       │             │
│             ┌─────────────┼─────────────┐         │             │
│             ▼             ▼             ▼         ▼             │
│        ┌────────┐   ┌──────────┐   ┌────────┐  ┌────────────┐   │
│        │ Docker │   │ Registry │   │  Tar   │  │endoflife.  │   │
│        │ Daemon │   │  (OCI)   │   │Archive │  │date API    │   │
│        └────────┘   └──────────┘   └────────┘  └────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Flow

1. **CLI Layer** → Parses commands and flags using Cobra
2. **Scanner Engine** → Orchestrates SBOM generation and EOL checking
3. **SBOM Generator** → Uses Syft to extract packages from container images
4. **EOL Database Manager** → Manages local SQLite database and API sync
5. **Matcher** → Matches packages using PURL, CPE, and name lookups

---

## 📁 Code Structure

```
eol-scanner/
├── main.go                      # 🚪 Application entry point
├── go.mod                       # 📦 Go module definition
├── go.sum                       # 🔒 Dependency checksums
│
├── cmd/                         # 🎮 CLI Commands (Cobra)
│   ├── root.go                  #    Root command & global flags
│   ├── scan.go                  #    Scan command implementation
│   ├── db.go                    #    Database management commands
│   └── version.go               #    Version command
│
└── core/                        # 🧠 Core Business Logic
    ├── scanning/                #    Scanning Engine
    │   └── scanning.go          #    Scanner, EOL status evaluation
    │
    ├── sbom/                    #    SBOM Generation
    │   ├── sbom_creation.go     #    Syft integration
    │   └── output_formats.go    #    SBOM format definitions
    │
    └── db/                      #    Database Management
        └── db_management.go     #    SQLite ops, API client, lookups
```

### Module Responsibilities

| Module | File | Purpose |
|--------|------|---------|
| **cmd** | `root.go` | Defines root command, global flags (`--db`, `--verbose`) |
| **cmd** | `scan.go` | Implements `scan` command with image analysis |
| **cmd** | `db.go` | Implements `db sync`, `db stats`, `db path` commands |
| **cmd** | `version.go` | Shows version, build date, git commit |
| **scanning** | `scanning.go` | Core scanning logic, EOL status evaluation |
| **sbom** | `sbom_creation.go` | Syft wrapper for SBOM generation |
| **sbom** | `output_formats.go` | Defines SBOM output format constants |
| **db** | `db_management.go` | SQLite database, API client, package lookups |

---

## ⚙️ How It Works

### 1. Database Initialization 📋

```
┌────────────────────────────────────────────────────────────┐
│                      Database Check                        │
├────────────────────────────────────────────────────────────┤
│  1. Check if ~/eol-db/eol.db exists                        │
│  2. If not exists → Full sync from endoflife.date API      │
│  3. If exists → Check last sync time                       │
│  4. If older than 7 days → Auto-update                     │
│  5. Load database for lookups                              │
└────────────────────────────────────────────────────────────┘
```

### 2. SBOM Generation 🔍

```
┌────────────────────────────────────────────────────────────┐
│                     SBOM Generation                        │
├────────────────────────────────────────────────────────────┤
│  Image Source (Docker/Registry/Tar)                        │
│         │                                                  │
│         ▼                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    Syft Engine                       │  │
│  │  • Extracts all layers                               │  │
│  │  • Catalogs packages (deb, rpm, apk, pip, npm...)    │  │
│  │  • Detects Linux distribution                        │  │
│  │  • Generates PURLs and CPEs                          │  │
│  └──────────────────────────────────────────────────────┘  │
│         │                                                  │
│         ▼                                                  │
│  SBOM with packages, OS info, PURLs, CPEs                  │
└────────────────────────────────────────────────────────────┘
```

### 3. Package Matching Strategy 🎯

The scanner uses a multi-tier matching approach:

```
┌────────────────────────────────────────────────────────────┐
│                  Package Matching Order                    │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  1️⃣  Exact PURL Match                                     │
│      pkg:pypi/django@4.2.0 → django product                │
│                    │                                       │
│                    ▼ (if no match)                         │
│  2️⃣  Distro-Specific PURL                                 │
│      pkg:deb/debian/python3.12 → Python product            │
│      pkg:rpm/fedora/mysql → MySQL product                  │
│                    │                                       │
│                    ▼ (if no match)                         │
│  3️⃣  Package Type PURL                                    │
│      pkg:npm/react → React product (if tracked)            │
│                    │                                       │
│                    ▼ (if no match)                         │
│  4️⃣  CPE Identifier Match                                 │
│      cpe:2.3:a:nginx:nginx:* → nginx product               │
│                    │                                       │
│                    ▼ (if no match)                         │
│  5️⃣  Name-Based Fallback                                  │
│      "python3.12" → Python product                         │
│      Checks: product names, aliases, repology IDs          │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 4. EOL Status Evaluation 📊

```
┌────────────────────────────────────────────────────────────┐
│                  EOL Status Determination                  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  For each matched product:                                 │
│                                                            │
│  1. Find matching release cycle (version → cycle)          │
│     e.g., "3.9.18" matches cycle "3.9"                     │
│                                                            │
│  2. Check EOL date or boolean:                             │
│     • If eol_boolean = true → ❌ EOL                      │
│     • If eol_date < today → ❌ EOL                        │
│     • If eol_date < today + forward_days → ⚠️ EOL Soon    │      
│     • Otherwise → ✅ Active                               │
│                                                            │
│  3. Calculate days until EOL (if applicable)               │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 5. OS Detection 🖥️

```
┌────────────────────────────────────────────────────────────┐
│                     OS EOL Detection                       │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Syft detects Linux distribution from:                     │
│  • /etc/os-release                                         │
│  • /etc/lsb-release                                        │
│  • /etc/debian_version, /etc/redhat-release, etc.          │
│                                                            │
│  Mapping:                                                  │
│  ┌──────────────┬──────────────────┐                       │
│  │ Distro ID    │ endoflife.date   │                       │
│  ├──────────────┼──────────────────┤                       │
│  │ ubuntu       │ ubuntu           │                       │
│  │ debian       │ debian           │                       │
│  │ alpine       │ alpine-linux     │                       │
│  │ rhel         │ rhel             │                       │
│  │ amzn         │ amazon-linux     │                       │
│  │ rocky        │ rocky-linux      │                       │
│  │ ...          │ ...              │                       │
│  └──────────────┴──────────────────┘                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 🗄️ Database Schema

The EOL database uses SQLite with the following schema:

### Tables

```sql
-- Categories (framework, lang, os, database, server-app)
CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    label TEXT,
    total_products INTEGER DEFAULT 0
);

-- Products (python, ubuntu, nginx, mysql, etc.)
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    category_id INTEGER,
    category_name TEXT,
    label TEXT,
    link TEXT,
    version_command TEXT,
    aliases TEXT,        -- JSON array
    tags TEXT            -- JSON array
);

-- Release Cycles (Python 3.9, Ubuntu 22.04, etc.)
CREATE TABLE cycles (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL,
    cycle TEXT NOT NULL,
    cycle_label TEXT,
    codename TEXT,
    release_date DATE,
    eol DATE,            -- EOL date (if known)
    eol_boolean INTEGER, -- 1 = already EOL
    latest_version TEXT,
    lts INTEGER DEFAULT 0,
    is_maintained INTEGER DEFAULT 0,
    UNIQUE(product_id, cycle)
);

-- Identifiers (PURL, CPE, Repology)
CREATE TABLE identifiers (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL,
    identifier_type TEXT NOT NULL,  -- 'purl', 'cpe', 'repology'
    identifier_value TEXT NOT NULL,
    UNIQUE(product_id, identifier_type, identifier_value)
);

-- Sync Metadata
CREATE TABLE sync_metadata (
    id INTEGER PRIMARY KEY,
    last_full_sync TIMESTAMP,
    last_update_check TIMESTAMP,
    categories_synced TEXT,  -- JSON array
    products_count INTEGER,
    cycles_count INTEGER,
    identifiers_count INTEGER
);
```

### Indexes

```sql
CREATE INDEX idx_products_category ON products(category_name);
CREATE INDEX idx_products_name ON products(name);
CREATE INDEX idx_cycles_product ON cycles(product_id);
CREATE INDEX idx_cycles_eol ON cycles(eol);
CREATE INDEX idx_identifiers_type ON identifiers(identifier_type);
CREATE INDEX idx_identifiers_value ON identifiers(identifier_value);
```

---

## 🔨 Building from Source

### Basic Build

```bash
# Clone the repository
git clone https://github.com/j0356/eol-scanner.git
cd eol-scanner

# Download dependencies
go mod download

# Build
go build -o eol-scanner .
```

### Production Build

```bash
# Build with optimizations and version info
CGO_ENABLED=1 go build \
    -ldflags "-s -w \
        -X github.com/j0356/eol-scanner/cmd.Version=1.0.0 \
        -X github.com/j0356/eol-scanner/cmd.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
        -X github.com/j0356/eol-scanner/cmd.GitCommit=$(git rev-parse --short HEAD)" \
    -o eol-scanner .
```

> **Note:** `CGO_ENABLED=1` is required for SQLite support.

### Cross-Compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o eol-scanner-linux-amd64 .

# Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc go build -o eol-scanner-linux-arm64 .

# macOS AMD64
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o eol-scanner-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o eol-scanner-darwin-arm64 .
```

### Running Tests

```bash
go test ./...
```

---

## ⚙️ Configuration

### Database Location

By default, the EOL database is stored at:

```
~/eol-db/eol.db
```

Override with the `--db` flag:

```bash
eol-scanner --db /custom/path/eol.db scan nginx:latest
```

### Default Categories

The following categories are synced by default:

| Category | Description | Examples |
|----------|-------------|----------|
| `framework` | Web/application frameworks | Django, Rails, Spring |
| `lang` | Programming languages | Python, Node.js, Go |
| `os` | Operating systems | Ubuntu, Debian, Alpine |
| `database` | Databases | MySQL, PostgreSQL, Redis |
| `server-app` | Server applications | Nginx, Apache, Tomcat |

### Environment Variables

Currently, EOL Scanner does not use environment variables. All configuration is done via command-line flags.

---

## 💡 Examples

### CI/CD Integration

```bash
#!/bin/bash
# Exit with error if any EOL components found

RESULT=$(eol-scanner scan --output json myapp:latest)
EOL_COUNT=$(echo "$RESULT" | jq '.eol_components')

if [ "$EOL_COUNT" -gt 0 ]; then
    echo "❌ Found $EOL_COUNT EOL components!"
    echo "$RESULT" | jq '.components[] | select(.status == "eol")'
    exit 1
fi

echo "✅ No EOL components found"
```

### GitHub Actions

```yaml
name: EOL Check

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly check

jobs:
  eol-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build EOL Scanner
        run: go build -o eol-scanner .

      - name: Sync EOL Database
        run: ./eol-scanner db sync

      - name: Scan Image
        run: |
          ./eol-scanner scan --days 90 --output json myapp:latest > eol-report.json

      - name: Check Results
        run: |
          EOL=$(jq '.eol_components' eol-report.json)
          if [ "$EOL" -gt 0 ]; then
            echo "::error::Found $EOL EOL components"
            exit 1
          fi
```

### Scanning Multiple Images

```bash
#!/bin/bash
IMAGES=(
    "nginx:latest"
    "python:3.9"
    "node:18"
    "postgres:14"
)

for image in "${IMAGES[@]}"; do
    echo "📦 Scanning $image..."
    eol-scanner scan --only-eol "$image"
    echo ""
done
```

### JSON Output Processing

```bash
# Get all EOL components as CSV
eol-scanner scan --output json myapp:latest | \
    jq -r '.components[] | select(.status == "eol") | [.name, .version, .eol_date] | @csv'

# Count by status
eol-scanner scan --output json myapp:latest | \
    jq '{
        total: .total_components,
        eol: .eol_components,
        eol_soon: .eol_soon_components,
        active: .active_components,
        unknown: .unknown_components
    }'
```

## 🙏 Acknowledgments

- [endoflife.date](https://endoflife.date) - The amazing EOL data source
- [Syft](https://github.com/anchore/syft) - SBOM generation engine
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [SQLite](https://sqlite.org) - Embedded database

---

<p align="center">
  Made with ❤️ for keeping your containers secure
</p>
