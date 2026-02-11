# CardVault - Character Card Index Server

A FastAPI server that indexes character card PNGs, detects duplicates, filters prohibited content, and provides a searchable REST API with a web dashboard.

## Features

- **Full-text search** across character names, descriptions, and creators (FTS5)
- **SQLite database** - scales to 500k+ cards with instant startup
- **Tag filtering** with NSFW/SFW options
- **Duplicate detection** using both content hash (MD5) and perceptual image hashing
- **Smart prohibited content filtering** with context-aware detection
- **Smart Import tool** - import from source folders without duplicates
- **Web dashboard** for browsing, searching, and managing cards
- **File watching** using polling (works with large collections)
- **Upload support** for adding new cards via API
- **Nextcloud integration** (optional) for triggering file scans

## Quick Start

### 1. Clone and setup

```bash
git clone https://github.com/Starkka15/cardvault.git
cd cardvault

# Create virtual environment
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
nano .env
```

Set your card directories:
```
CARD_DIRS=/path/to/your/CharacterCards
CARD_PORT=8787
```

### 3. Run

```bash
./venv/bin/python server.py
```

Visit http://localhost:8787 to access the web dashboard.

## Production Setup (systemd)

```bash
# Copy files to /opt/card-index-server
sudo mkdir -p /opt/card-index-server
sudo cp server.py requirements.txt card-index.service .env /opt/card-index-server/

# Create index directory
sudo mkdir -p /var/lib/card-index

# Install service
sudo cp card-index.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable card-index
sudo systemctl start card-index
```

## API Endpoints

### Search & Browse
| Endpoint | Description |
|----------|-------------|
| `GET /` | Web dashboard |
| `GET /api/cards` | Search cards with filters |
| `GET /api/cards/{folder}/{filename}` | Get full card metadata |
| `GET /cards/{folder}/{filename}` | Get card PNG image |
| `GET /api/stats` | Index statistics |
| `GET /api/tags` | List all tags with counts |

### Management
| Endpoint | Description |
|----------|-------------|
| `POST /api/cards/upload` | Upload a new card |
| `DELETE /api/cards/delete` | Delete a card |
| `GET /api/duplicates` | Get duplicate groups |
| `DELETE /api/duplicates/clean` | Remove duplicates (keep one) |
| `POST /api/duplicates/ignore` | Mark group as non-duplicate |
| `GET /api/cards/similar` | Find similar cards |
| `GET /api/quarantine` | View quarantined cards for manual review |

### Index Management
| Endpoint | Description |
|----------|-------------|
| `GET /api/index/status` | Scan status |
| `POST /api/index/rescan` | Trigger full rescan |
| `POST /api/nextcloud/scan` | Trigger Nextcloud file scan |

### Smart Import
| Endpoint | Description |
|----------|-------------|
| `POST /api/import/scan` | Scan source directory for importable cards |
| `POST /api/import/execute` | Import selected cards |
| `GET /api/import/quarantine` | View cards needing manual review |
| `POST /api/import/quarantine/review` | Approve or reject quarantined card |

## Search Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `q` | Search query | `?q=vampire` |
| `tags` | Filter by tags (comma-separated) | `?tags=Female,Fantasy` |
| `nsfw` | Filter by NSFW status | `?nsfw=false` |
| `creator` | Filter by creator | `?creator=SomeCreator` |
| `folder` | Filter by folder | `?folder=chub` |
| `limit` | Results per page (max 200) | `?limit=50` |
| `offset` | Pagination offset | `?offset=100` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CARD_DIRS` | (required) | List of directories to index (see note below) |
| `CARD_HOST` | `0.0.0.0` | Host to bind to |
| `CARD_PORT` | `8787` | Port to bind to |
| `CARD_DETECT_DUPES` | `true` | Enable duplicate detection |
| `CARD_DB_FILE` | `/var/lib/card-index/cards.db` | SQLite database file |
| `CARD_WATCH_FILES` | `true` | Enable file watching for auto-detection |
| `CARD_RESCAN_STARTUP` | `false` | Rescan all files on startup |
| `LOREBOOK_DIRS` | (optional) | List of lorebook directories (same format as CARD_DIRS) |
| `NEXTCLOUD_USER` | (optional) | Nextcloud user for file scan integration |

### Path Separator for Multiple Directories

Use colon (`:`) to separate multiple directories - works on all platforms:

```
CARD_DIRS=C:/Characters/folder1:D:/Characters/folder2
CARD_DIRS=/data/cards:/mnt/more-cards
```

Windows drive letters (like `C:`) are automatically detected and handled correctly.

## Content Quarantine System

CardVault uses smart context-aware content filtering to flag cards for manual review. **Cards are never automatically deleted by the system** - they remain fully accessible and indexed, but flagged items appear in the Quarantine tab for your review and manual action.

### How It Works

When a card is indexed, CardVault checks:
1. **Tags** - Exact matches against a blocklist
2. **Description & First Message** - Pattern matching for prohibited content
3. **Age References** - Context-aware detection with backstory consideration
4. **NSFW Context** - Analyzes if concerning patterns appear in NSFW contexts

Cards that match patterns are:
- **Fully indexed and accessible** - searchable, viewable, downloadable
- **Logged to quarantine** - visible in Quarantine tab for manual review
- **Never auto-deleted** - you have full control

### Review Statuses

- **block** (High Priority) - Strong match, recommended for manual review
- **quarantine** (Review) - Potential match, may be context-dependent

### Customizing the Blocklists

The blocklists are defined at the top of `server.py` (around lines 72-117):

```python
# Exact tag matches (case-insensitive)
BLOCKED_TAGS_EXACT = {
    "child", "children", "underage", "minor", "minors",
    "kid", "kids", "toddler", "infant", "preteen", ...
}

# Regex patterns for tags
BLOCKED_PATTERNS = [re.compile(r'\bloli'), re.compile(r'\bshota'), ...]

# Strict description patterns (always block)
BLOCKED_DESCRIPTION_PATTERNS_STRICT = [
    re.compile(r'\b(underage|under-age|under age)\b', re.IGNORECASE),
    ...
]

# Context-sensitive age patterns (analyzed with surrounding text)
AGE_PATTERNS_CONTEXT = [
    re.compile(r'\bage\s*[:\-]?\s*([1-9]|1[0-7])\b', re.IGNORECASE),
    ...
]
```

To customize:
1. Edit `server.py` directly
2. Modify the sets/lists as needed
3. Restart the server

### Viewing Quarantined Cards

Check which cards are flagged for review:
- **Web UI**: Click "Quarantine" tab in the dashboard
- **API**: `GET /api/quarantine`

Each quarantined card shows:
- File path and status (block/quarantine)
- Matched patterns and reason
- View and Delete action buttons

## Web Dashboard

Access the dashboard at `http://your-server:8787/`

Features:
- **Search** - Full-text search with tag filtering
- **Lorebooks** - Browse and search lorebook collection
- **Duplicates** - View and manage duplicate cards
- **Quarantine** - Review and manage flagged content
- **Statistics** - Total cards, NSFW count, top tags/creators
- **Card Details** - Click any card to view full info and import

## Integration with PocketTavern

This server is designed to work with the PocketTavern Android app. Configure the CardVault URL in PocketTavern settings to:
- Browse your card collection on mobile
- Import cards to SillyTavern
- Upload characters from the app

## License

MIT
