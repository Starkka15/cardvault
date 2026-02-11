#!/usr/bin/env python3
"""
Character Card Index Server - SQLite Edition
Monitors folders for character cards, indexes metadata, serves search API.
Flags prohibited content for manual review and detects duplicates.

Uses SQLite + FTS5 for fast full-text search at scale (200k+ cards).

Configuration via environment variables:
  CARD_DIRS           - Colon-separated list of directories to index
                        Windows drive letters (C:, D:) are detected automatically
                        Example: C:/Cards/folder1:D:/Cards/folder2
  CARD_HOST           - Host to bind to (default: 0.0.0.0)
  CARD_PORT           - Port to bind to (default: 8787)
  CARD_DETECT_DUPES   - Detect duplicates (default: true)
  CARD_DB_FILE        - SQLite database file (default: /var/lib/card-index/cards.db)
"""

import os
import sys
import re
import json
import base64
import struct
import hashlib
import asyncio
import logging
import subprocess
import sqlite3
import threading
import zlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict, field
from contextlib import contextmanager
from io import BytesIO

try:
    from PIL import Image
    import imagehash
    IMAGE_HASH_AVAILABLE = True
except ImportError:
    IMAGE_HASH_AVAILABLE = False
    logging.warning("imagehash/Pillow not installed - image duplicate detection disabled")

from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileMovedEvent

from fastapi import FastAPI, Query, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import uvicorn
import shutil
import platform

def parse_path_list(path_string: str, default: str = "") -> list:
    """
    Parse a list of paths from environment variable.
    Handles both Unix (:) and Windows (;) separators.
    Windows paths like C:/path are handled correctly.
    """
    if not path_string:
        return [default] if default else []

    # If semicolon is present, use it as separator (Windows-style)
    if ";" in path_string:
        return [p.strip() for p in path_string.split(";") if p.strip()]

    # On Windows or if path contains drive letters, be careful with colons
    if platform.system() == "Windows" or (len(path_string) > 1 and path_string[1] == ":"):
        # Split on colon but rejoin drive letters (e.g., C:)
        # Pattern: split, then rejoin single letters with following path
        parts = path_string.split(":")
        paths = []
        i = 0
        while i < len(parts):
            part = parts[i].strip()
            # Check if this is a drive letter (single char, next part starts with / or \)
            if len(part) == 1 and part.isalpha() and i + 1 < len(parts):
                # Rejoin with next part
                paths.append(f"{part}:{parts[i + 1].strip()}")
                i += 2
            elif part:
                paths.append(part)
                i += 1
            else:
                i += 1
        return paths

    # Unix-style: simple colon split
    return [p.strip() for p in path_string.split(":") if p.strip()]

# Configuration from environment
CARD_DIRS = parse_path_list(os.environ.get("CARD_DIRS", ""), "/data/CharacterCards")
LOREBOOK_DIRS = parse_path_list(os.environ.get("LOREBOOK_DIRS", ""))
HOST = os.environ.get("CARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("CARD_PORT", "8787"))
RECURSIVE = os.environ.get("CARD_RECURSIVE", "true").lower() == "true"
# AUTO_DELETE_PROHIBITED removed - now using manual review for prohibited content
DETECT_DUPLICATES = os.environ.get("CARD_DETECT_DUPES", "true").lower() == "true"
NEXTCLOUD_USER = os.environ.get("NEXTCLOUD_USER", "")
DB_FILE = os.environ.get("CARD_DB_FILE", "/var/lib/card-index/cards.db")
RESCAN_ON_STARTUP = os.environ.get("CARD_RESCAN_STARTUP", "false").lower() == "true"
WATCH_FILES = os.environ.get("CARD_WATCH_FILES", "true").lower() == "true"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Log parsed directories at startup for debugging
logger.info(f"CARD_DIRS raw env: {os.environ.get('CARD_DIRS', '(not set)')}")
logger.info(f"CARD_DIRS parsed: {CARD_DIRS}")
for i, d in enumerate(CARD_DIRS):
    exists = os.path.exists(d)
    logger.info(f"  [{i+1}] {d} - {'EXISTS' if exists else 'NOT FOUND'}")

# Prohibited content detection (blocked regardless of NSFW status)
BLOCKED_TAGS_EXACT = {
    "child", "children", "underage", "minor", "minors",
    "kid", "kids", "toddler", "infant", "preteen", "prepubescent",
    "young child", "little girl", "little boy", "cub", "cubs",
    "pedophilia", "pedo", "cp", "csam", "jailbait", "incest"
}
BLOCKED_PATTERNS = [re.compile(r'\bloli'), re.compile(r'\bshota'), re.compile(r'\brape')]

# Additional patterns for description scanning (strict - always block)
BLOCKED_DESCRIPTION_PATTERNS_STRICT = [
    re.compile(r'\b(underage|under-age|under age)\b', re.IGNORECASE),
    re.compile(r'\b(child|children|kid|kids)\b.*\b(sex|rape|nsfw|erotic|lewd)\b', re.IGNORECASE),
    re.compile(r'\b(sex|rape|nsfw|erotic|lewd)\b.*\b(child|children|kid|kids)\b', re.IGNORECASE),
    re.compile(r'\bloli\b', re.IGNORECASE),
    re.compile(r'\bshota\b', re.IGNORECASE),
    re.compile(r'\b(young|little)\s+(girl|boy)\b.*\b(sex|rape|nsfw|erotic|lewd)\b', re.IGNORECASE),
    re.compile(r'\bpedophil', re.IGNORECASE),
    re.compile(r'\bminor\b.*\b(sex|sexual|rape|erotic)\b', re.IGNORECASE),
    re.compile(r'\b(preteen|pre-teen)\b', re.IGNORECASE),
]

# Context-sensitive age patterns (need additional analysis)
AGE_PATTERNS_CONTEXT = [
    re.compile(r'\bage\s*[:\-]?\s*([1-9]|1[0-7])\b', re.IGNORECASE),
    re.compile(r'\b([1-9]|1[0-7])[-\s]*(years?|yrs?|y/?o)[-\s]*old\b', re.IGNORECASE),
    re.compile(r'\b(is|being|currently|now)\s+([1-9]|1[0-7])(\s|$)', re.IGNORECASE),
]

# Whitelist patterns - age mentions that are usually safe
AGE_WHITELIST_PATTERNS = [
    re.compile(r'\b(\d+)\s*years?\s*ago\b', re.IGNORECASE),  # "5 years ago"
    re.compile(r'\bfor\s+(\d+)\s*years?\b', re.IGNORECASE),  # "for 10 years"
    re.compile(r'\b(was|were|at|when|since)\s+(age\s+)?([1-9]|1[0-7])\b', re.IGNORECASE),  # past tense
    re.compile(r'\b(grew up|raised|born|childhood|backstory|history)\b', re.IGNORECASE),  # backstory context
]

# Adult age patterns - if present, minor age mentions might be backstory
ADULT_AGE_PATTERNS = [
    re.compile(r'\bage\s*[:\-]?\s*(1[89]|[2-9]\d|\d{3,})\b', re.IGNORECASE),  # age: 18+
    re.compile(r'\b(1[89]|[2-9]\d)[-\s]*(years?|yrs?|y/?o)[-\s]*old\b', re.IGNORECASE),  # "25 years old"
    re.compile(r'\b(is|currently|now)\s+(1[89]|[2-9]\d)\b', re.IGNORECASE),  # "is 25"
    re.compile(r'\b(adult|mature|grown|elderly|ancient|immortal|ageless)\b', re.IGNORECASE),
]

# Legacy combined list for backwards compatibility
BLOCKED_DESCRIPTION_PATTERNS = BLOCKED_DESCRIPTION_PATTERNS_STRICT + AGE_PATTERNS_CONTEXT

# NSFW tag indicators
NSFW_TAGS = {
    "nsfw", "explicit", "adult", "18+", "mature", "r18", "r-18",
    "sexual", "erotic", "lewd", "smut", "porn", "hentai",
    "sex", "nude", "naked", "xxx", "fetish", "kink",
    "bdsm", "bondage", "dominatrix", "submissive",
    "slutty", "whore", "prostitute", "hooker",
    "breeding", "impregnation", "pregnancy kink",
    "incest", "taboo", "forbidden",
    "gore", "violence", "torture", "snuff",
    "rape", "non-con", "noncon", "dubcon", "dub-con",
    "futanari", "futa", "dickgirl",
    "furry", "kemono", "anthro",
    "monster", "tentacle", "oviposition", "vore",
    "femdom", "maledom", "cuckold", "ntr",
    "ahegao", "gangbang", "orgy", "threesome",
    "blowjob", "handjob", "footjob", "titjob",
    "anal", "oral", "creampie", "cumshot",
    "exhibitionist", "voyeur",
}

# NSFW patterns to search in descriptions
NSFW_DESCRIPTION_PATTERNS = [
    re.compile(r'\b(nsfw|explicit|18\+|adult only|mature content)\b', re.IGNORECASE),
    re.compile(r'\b(sex|sexual|erotic|lewd|smut)\b', re.IGNORECASE),
    re.compile(r'\b(fuck|cock|dick|penis|pussy|vagina|cunt|tits|breasts?|nipples?)\b', re.IGNORECASE),
    re.compile(r'\b(orgasm|climax|moan|cum|cumming|ejaculat)\b', re.IGNORECASE),
    re.compile(r'\b(nude|naked|strip|undress)\b', re.IGNORECASE),
    re.compile(r'\b(masturbat|fingering|handjob|blowjob|fellatio|cunnilingus)\b', re.IGNORECASE),
    re.compile(r'\b(bdsm|bondage|domination|submission|sadis|masochis)\b', re.IGNORECASE),
    re.compile(r'\b(rape|non-?con|forced|violated)\b', re.IGNORECASE),
    re.compile(r'\b(hentai|ahegao|tentacle|vore)\b', re.IGNORECASE),
    re.compile(r'\b(slut|whore|bitch|prostitut)\b', re.IGNORECASE),
    re.compile(r'\b(breed|impregnate|creampie|knocked up)\b', re.IGNORECASE),
    re.compile(r'\b(incest|step-?(mom|dad|sis|bro|mother|father|sister|brother))\b', re.IGNORECASE),
    re.compile(r'\bwill\s+(fuck|have sex|sleep with|breed)\b', re.IGNORECASE),
    re.compile(r'\b(sexually|intimately)\s+(aggressive|dominant|submissive)\b', re.IGNORECASE),
    re.compile(r'\bloves?\s+(sex|fucking|cock|dick|being fucked)\b', re.IGNORECASE),
    re.compile(r'\b(horny|aroused|turned on|in heat)\b', re.IGNORECASE),
]


def name_similarity(name1: str, name2: str) -> float:
    """Check if two names are similar enough to be considered the same character."""
    n1 = re.sub(r'[^a-z0-9\s]', '', name1.lower()).split()
    n2 = re.sub(r'[^a-z0-9\s]', '', name2.lower()).split()

    if not n1 or not n2:
        return 0.0

    significant1 = {w for w in n1 if len(w) > 2}
    significant2 = {w for w in n2 if len(w) > 2}

    if not significant1 or not significant2:
        return 1.0 if n1[0] == n2[0] else 0.0

    common = significant1 & significant2
    if common:
        return len(common) / min(len(significant1), len(significant2))

    return 0.0


def check_prohibited_tags(tags: List[str]) -> Tuple[bool, set]:
    """Check if tags contain prohibited content."""
    tags_lower = [t.lower() for t in tags]
    blocked_found = set()

    for tag in tags_lower:
        if tag in BLOCKED_TAGS_EXACT:
            blocked_found.add(tag)
        else:
            for pattern in BLOCKED_PATTERNS:
                if pattern.search(tag):
                    blocked_found.add(tag)
                    break

    return bool(blocked_found), blocked_found


def check_prohibited_description(description: str) -> Tuple[bool, set]:
    """Check if description contains prohibited content."""
    if not description:
        return False, set()

    blocked_found = set()

    for pattern in BLOCKED_DESCRIPTION_PATTERNS:
        match = pattern.search(description)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(description), match.end() + 20)
            snippet = description[start:end].replace('\n', ' ')
            blocked_found.add(f"desc: ...{snippet}...")

    return bool(blocked_found), blocked_found


def check_prohibited_content(tags: List[str], description: str = "", first_mes: str = "") -> Tuple[bool, set]:
    """Check tags and description for prohibited content."""
    blocked_found = set()

    tag_prohibited, tag_matches = check_prohibited_tags(tags)
    blocked_found.update(tag_matches)

    desc_prohibited, desc_matches = check_prohibited_description(description)
    blocked_found.update(desc_matches)

    first_mes_prohibited, first_mes_matches = check_prohibited_description(first_mes)
    blocked_found.update(first_mes_matches)

    is_prohibited = tag_prohibited or desc_prohibited or first_mes_prohibited
    return is_prohibited, blocked_found


def check_prohibited_content_smart(tags: List[str], description: str = "", first_mes: str = "",
                                    personality: str = "", scenario: str = "") -> Tuple[str, set, str]:
    """
    Smart context-aware prohibited content check.

    Returns: (status, matches, reason)
        status: "block" | "quarantine" | "safe"
        matches: set of matched patterns
        reason: human-readable explanation
    """
    blocked_found = set()
    full_text = f"{description} {first_mes} {personality} {scenario}"

    # Check tags first - exact tag matches are always blocked
    tag_prohibited, tag_matches = check_prohibited_tags(tags)
    if tag_prohibited:
        return "block", tag_matches, "Prohibited tags found"

    # Check strict patterns - always block
    for pattern in BLOCKED_DESCRIPTION_PATTERNS_STRICT:
        match = pattern.search(full_text)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(full_text), match.end() + 30)
            snippet = full_text[start:end].replace('\n', ' ')
            blocked_found.add(f"...{snippet}...")

    if blocked_found:
        return "block", blocked_found, "Strict prohibited content pattern"

    # Check context-sensitive age patterns
    age_matches = []
    for pattern in AGE_PATTERNS_CONTEXT:
        for match in pattern.finditer(full_text):
            age_matches.append((match.start(), match.end(), match.group()))

    if not age_matches:
        return "safe", set(), "No prohibited content found"

    # Check if adult age is mentioned (suggests minor age is backstory)
    has_adult_age = any(p.search(full_text) for p in ADULT_AGE_PATTERNS)

    # Check for whitelist patterns near the age mention
    has_whitelist_context = any(p.search(full_text) for p in AGE_WHITELIST_PATTERNS)

    # Analyze each age match
    for start, end, matched_text in age_matches:
        # Get surrounding context (100 chars each side)
        context_start = max(0, start - 100)
        context_end = min(len(full_text), end + 100)
        context = full_text[context_start:context_end].lower()

        # Check if this specific mention has whitelist context
        local_whitelist = any(p.search(context) for p in AGE_WHITELIST_PATTERNS)
        local_adult = any(p.search(context) for p in ADULT_AGE_PATTERNS)

        if local_whitelist or local_adult:
            # Likely backstory context
            continue

        # Check for explicit NSFW context near the age
        nsfw_near_age = any(p.search(context) for p in NSFW_DESCRIPTION_PATTERNS[:10])

        if nsfw_near_age:
            blocked_found.add(f"Minor age + NSFW context: ...{context[50:150]}...")
            return "block", blocked_found, "Minor age mentioned in NSFW context"

    # If we found age mentions but also adult age or whitelist patterns
    if age_matches and (has_adult_age or has_whitelist_context):
        snippets = {f"Age mention (likely backstory): {m[2]}" for m in age_matches[:3]}
        return "safe", snippets, "Minor age appears to be backstory (adult age also present)"

    # Age mention without clear context - quarantine for review
    if age_matches:
        snippets = set()
        for start, end, matched_text in age_matches[:3]:
            context_start = max(0, start - 40)
            context_end = min(len(full_text), end + 40)
            snippet = full_text[context_start:context_end].replace('\n', ' ')
            snippets.add(f"...{snippet}...")
        return "quarantine", snippets, "Minor age mentioned - needs manual review"

    return "safe", set(), "No prohibited content found"


def parse_name_from_filename(filename: str, extensions: List[str] = None) -> Tuple[str, str]:
    """
    Parse name and creator from filename.

    Common formats:
    - "Creator - Name - ID.ext"
    - "Creator - Name.ext"
    - "Name.ext"

    Returns: (name, creator) tuple
    """
    if extensions is None:
        extensions = ['.card.png', '.png', '.card']
    # Remove extensions
    name = filename
    for ext in extensions:
        if name.lower().endswith(ext.lower()):
            name = name[:-len(ext)]
            break

    # Split by " - " separator
    parts = name.split(' - ')

    if len(parts) >= 3:
        # Format: "Creator - Name - ID" or "Creator - Name with - dashes - ID"
        creator = parts[0].strip()
        # Check if last part looks like an ID (mostly digits)
        last_part = parts[-1].strip()
        if last_part.isdigit() or (len(last_part) > 4 and sum(c.isdigit() for c in last_part) > len(last_part) * 0.5):
            # Last part is ID, name is everything in between
            char_name = ' - '.join(parts[1:-1]).strip()
        else:
            # No ID, name is everything after creator
            char_name = ' - '.join(parts[1:]).strip()
        return char_name, creator
    elif len(parts) == 2:
        # Format: "Creator - Name" or "Name - ID"
        first, second = parts[0].strip(), parts[1].strip()
        # If second part looks like an ID, first is the name
        if second.isdigit() or (len(second) > 4 and sum(c.isdigit() for c in second) > len(second) * 0.5):
            return first, "Unknown"
        else:
            # Assume "Creator - Name"
            return second, first
    else:
        # Just a name
        return name.strip(), "Unknown"


def check_nsfw_content(tags: List[str], description: str = "", first_mes: str = "") -> bool:
    """Check if content should be marked as NSFW."""
    tags_lower = {t.lower() for t in tags}
    if tags_lower & NSFW_TAGS:
        return True

    text_to_check = f"{description} {first_mes}"
    for pattern in NSFW_DESCRIPTION_PATTERNS:
        if pattern.search(text_to_check):
            return True

    return False


@dataclass
class CardEntry:
    """Card data structure - matches original API response format."""
    file: str
    path: str
    folder: str
    name: str
    creator: str
    tags: List[str]
    nsfw: bool
    description_preview: str
    first_mes_preview: str
    indexed_at: str
    content_hash: str = ""
    image_hash: str = ""


class CardIndexDB:
    """SQLite-based card index with FTS5 full-text search."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._local = threading.local()

        # In-memory caches for image hash comparison (needed for fuzzy matching)
        self.image_hash_objects: Dict[str, Any] = {}

        # Scan status
        self.scan_status = {"running": False, "progress": 0, "total": 0, "last_scan": None}

        # Initialize database
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent read/write
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self._local.conn

    @contextmanager
    def _cursor(self):
        """Context manager for database cursor."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def _init_db(self):
        """Initialize database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._cursor() as cur:
            # Main cards table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    file TEXT NOT NULL,
                    folder TEXT NOT NULL,
                    name TEXT NOT NULL,
                    creator TEXT DEFAULT 'Unknown',
                    tags TEXT DEFAULT '[]',
                    nsfw INTEGER DEFAULT 0,
                    description_preview TEXT DEFAULT '',
                    first_mes_preview TEXT DEFAULT '',
                    indexed_at TEXT NOT NULL,
                    content_hash TEXT DEFAULT '',
                    image_hash TEXT DEFAULT '',
                    file_mtime REAL DEFAULT 0,
                    prohibited INTEGER DEFAULT 0
                )
            """)
            
            # Add prohibited column to existing cards tables (migration)
            cur.execute("PRAGMA table_info(cards)")
            columns = [row[1] for row in cur.fetchall()]
            if 'prohibited' not in columns:
                cur.execute("ALTER TABLE cards ADD COLUMN prohibited INTEGER DEFAULT 0")
                logger.info("Added 'prohibited' column to cards table")

            # FTS5 virtual table for full-text search
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cards_fts USING fts5(
                    name,
                    creator,
                    description_preview,
                    tags_text,
                    content='cards',
                    content_rowid='id',
                    tokenize='porter unicode61'
                )
            """)

            # Triggers to keep FTS in sync
            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_ai AFTER INSERT ON cards BEGIN
                    INSERT INTO cards_fts(rowid, name, creator, description_preview, tags_text)
                    VALUES (new.id, new.name, new.creator, new.description_preview, new.tags);
                END
            """)

            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_ad AFTER DELETE ON cards BEGIN
                    INSERT INTO cards_fts(cards_fts, rowid, name, creator, description_preview, tags_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description_preview, old.tags);
                END
            """)

            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS cards_au AFTER UPDATE ON cards BEGIN
                    INSERT INTO cards_fts(cards_fts, rowid, name, creator, description_preview, tags_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description_preview, old.tags);
                    INSERT INTO cards_fts(rowid, name, creator, description_preview, tags_text)
                    VALUES (new.id, new.name, new.creator, new.description_preview, new.tags);
                END
            """)

            # Quarantine - cards flagged for manual review
            cur.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    matches TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    quarantined_at TEXT NOT NULL
                )
            """)

            # Migrate old data from prohibited_deleted to quarantine
            try:
                cur.execute("""
                    INSERT OR IGNORE INTO quarantine (path, matches, status, reason, quarantined_at)
                    SELECT path, tags, 'flagged', 'Legacy prohibited detection', deleted_at
                    FROM prohibited_deleted
                """)
                cur.execute("DROP TABLE IF EXISTS prohibited_deleted")
            except sqlite3.OperationalError:
                pass  # Table might not exist or already migrated

            # Ignored duplicates
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ignored_duplicates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    paths_hash TEXT UNIQUE NOT NULL,
                    paths TEXT NOT NULL
                )
            """)

            # Import quarantine - cards flagged for manual review
            cur.execute("""
                CREATE TABLE IF NOT EXISTS import_quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_path TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    creator TEXT DEFAULT 'Unknown',
                    status TEXT DEFAULT 'pending',
                    reason TEXT DEFAULT '',
                    matches TEXT DEFAULT '[]',
                    scanned_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    decision TEXT
                )
            """)

            # Import scan results cache
            cur.execute("""
                CREATE TABLE IF NOT EXISTS import_scan_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_dir TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    total_files INTEGER DEFAULT 0,
                    new_cards INTEGER DEFAULT 0,
                    duplicates INTEGER DEFAULT 0,
                    prohibited INTEGER DEFAULT 0,
                    quarantined INTEGER DEFAULT 0,
                    results TEXT DEFAULT '{}'
                )
            """)

            # Lorebooks table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS lorebooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    file TEXT NOT NULL,
                    folder TEXT NOT NULL,
                    name TEXT NOT NULL,
                    creator TEXT DEFAULT 'Unknown',
                    description TEXT DEFAULT '',
                    topics TEXT DEFAULT '[]',
                    entry_count INTEGER DEFAULT 0,
                    token_count INTEGER DEFAULT 0,
                    keywords TEXT DEFAULT '',
                    star_count INTEGER DEFAULT 0,
                    chub_id INTEGER DEFAULT 0,
                    nsfw INTEGER DEFAULT 0,
                    indexed_at TEXT NOT NULL,
                    content_hash TEXT DEFAULT ''
                )
            """)

            # FTS5 for lorebook search
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS lorebooks_fts USING fts5(
                    name,
                    creator,
                    description,
                    keywords,
                    topics_text,
                    content='lorebooks',
                    content_rowid='id',
                    tokenize='porter unicode61'
                )
            """)

            # Lorebook FTS triggers
            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS lorebooks_ai AFTER INSERT ON lorebooks BEGIN
                    INSERT INTO lorebooks_fts(rowid, name, creator, description, keywords, topics_text)
                    VALUES (new.id, new.name, new.creator, new.description, new.keywords,
                            REPLACE(REPLACE(new.topics, '[', ''), ']', ''));
                END
            """)
            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS lorebooks_ad AFTER DELETE ON lorebooks BEGIN
                    INSERT INTO lorebooks_fts(lorebooks_fts, rowid, name, creator, description, keywords, topics_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description, old.keywords,
                            REPLACE(REPLACE(old.topics, '[', ''), ']', ''));
                END
            """)
            cur.execute("""
                CREATE TRIGGER IF NOT EXISTS lorebooks_au AFTER UPDATE ON lorebooks BEGIN
                    INSERT INTO lorebooks_fts(lorebooks_fts, rowid, name, creator, description, keywords, topics_text)
                    VALUES ('delete', old.id, old.name, old.creator, old.description, old.keywords,
                            REPLACE(REPLACE(old.topics, '[', ''), ']', ''));
                    INSERT INTO lorebooks_fts(rowid, name, creator, description, keywords, topics_text)
                    VALUES (new.id, new.name, new.creator, new.description, new.keywords,
                            REPLACE(REPLACE(new.topics, '[', ''), ']', ''));
                END
            """)

            # Indexes for fast lookups
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_content_hash ON cards(content_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_image_hash ON cards(image_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_folder ON cards(folder)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_creator ON cards(creator)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_nsfw ON cards(nsfw)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cards_path ON cards(path)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_lorebooks_creator ON lorebooks(creator)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_lorebooks_nsfw ON lorebooks(nsfw)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_lorebooks_chub_id ON lorebooks(chub_id)")

        logger.info(f"Database initialized at {self.db_path}")

    def _row_to_entry(self, row: sqlite3.Row) -> CardEntry:
        """Convert database row to CardEntry."""
        tags = json.loads(row['tags']) if row['tags'] else []
        return CardEntry(
            file=row['file'],
            path=row['path'],
            folder=row['folder'],
            name=row['name'],
            creator=row['creator'],
            tags=tags,
            nsfw=bool(row['nsfw']),
            description_preview=row['description_preview'],
            first_mes_preview=row['first_mes_preview'],
            indexed_at=row['indexed_at'],
            content_hash=row['content_hash'] or '',
            image_hash=row['image_hash'] or ''
        )

    def get_card_count(self) -> int:
        """Get total number of indexed cards."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            return cur.fetchone()[0]

    def get_card_by_path(self, path: str) -> Optional[CardEntry]:
        """Get card by file path."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM cards WHERE path = ?", (path,))
            row = cur.fetchone()
            return self._row_to_entry(row) if row else None

    def get_all_cards(self) -> Dict[str, CardEntry]:
        """Get all cards as dict (for compatibility)."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM cards")
            return {row['path']: self._row_to_entry(row) for row in cur.fetchall()}

    def card_exists(self, path: str) -> bool:
        """Check if card exists in index."""
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM cards WHERE path = ? LIMIT 1", (path,))
            return cur.fetchone() is not None

    def get_file_mtime(self, path: str) -> Optional[float]:
        """Get stored file modification time."""
        with self._cursor() as cur:
            cur.execute("SELECT file_mtime FROM cards WHERE path = ?", (path,))
            row = cur.fetchone()
            return row[0] if row else None

    def calculate_image_hash(self, filepath: str) -> Optional[str]:
        """Calculate perceptual hash of image."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        try:
            with Image.open(filepath) as img:
                phash = imagehash.dhash(img, hash_size=12)
                self.image_hash_objects[filepath] = phash
                return str(phash)
        except Exception as e:
            logger.debug(f"Failed to hash image {filepath}: {e}")
            return None

    def find_similar_image(self, filepath: str, hash_obj, threshold: int = 12) -> Optional[str]:
        """Find existing card with similar image hash."""
        if not IMAGE_HASH_AVAILABLE:
            return None
        for existing_path, existing_hash in self.image_hash_objects.items():
            if existing_path == filepath:
                continue
            distance = hash_obj - existing_hash
            if distance <= threshold:
                return existing_path
        return None

    def extract_metadata(self, filepath: str) -> Optional[dict]:
        """Extract chara metadata from PNG tEXt chunk."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            if data[:8] != b'\x89PNG\r\n\x1a\n':
                return None

            pos = 8
            while pos < len(data):
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]

                if chunk_type == b'tEXt':
                    chunk_data = data[pos+8:pos+8+length]
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        key = chunk_data[:null_pos]
                        value = chunk_data[null_pos+1:]
                        if key == b'chara':
                            decoded = json.loads(base64.b64decode(value))
                            return decoded

                if chunk_type == b'IEND':
                    break

                pos += 12 + length

            return None
        except Exception as e:
            logger.error(f"Error extracting metadata from {filepath}: {e}")
            return None

    def write_metadata(self, filepath: str, metadata: dict) -> bool:
        """Write updated metadata back to PNG tEXt chunk."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            if data[:8] != b'\x89PNG\r\n\x1a\n':
                logger.error(f"Not a valid PNG: {filepath}")
                return False

            # Find and replace the chara tEXt chunk
            pos = 8
            chunks_before = []
            chunks_after = []
            found_chara = False
            iend_chunk = None

            while pos < len(data):
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                chunk_data = data[pos+8:pos+8+length]
                chunk_crc = data[pos+8+length:pos+12+length]

                if chunk_type == b'IEND':
                    iend_chunk = data[pos:pos+12+length]
                    break

                if chunk_type == b'tEXt':
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos != -1:
                        key = chunk_data[:null_pos]
                        if key == b'chara':
                            found_chara = True
                            pos += 12 + length
                            continue

                if not found_chara:
                    chunks_before.append(data[pos:pos+12+length])
                else:
                    chunks_after.append(data[pos:pos+12+length])

                pos += 12 + length

            # Create new chara chunk
            encoded_metadata = base64.b64encode(json.dumps(metadata).encode('utf-8'))
            new_chunk_data = b'chara\x00' + encoded_metadata
            new_chunk_length = struct.pack('>I', len(new_chunk_data))
            new_chunk_crc = struct.pack('>I', zlib.crc32(b'tEXt' + new_chunk_data) & 0xffffffff)
            new_chara_chunk = new_chunk_length + b'tEXt' + new_chunk_data + new_chunk_crc

            # Reassemble PNG
            new_data = data[:8]  # PNG signature
            for chunk in chunks_before:
                new_data += chunk
            new_data += new_chara_chunk
            for chunk in chunks_after:
                new_data += chunk
            if iend_chunk:
                new_data += iend_chunk

            # Write back
            with open(filepath, 'wb') as f:
                f.write(new_data)

            return True

        except Exception as e:
            logger.error(f"Error writing metadata to {filepath}: {e}")
            return False

    def add_quarantine(self, path: str, matches: List[str], status: str, reason: str):
        """Add a card to quarantine for manual review."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO quarantine (path, matches, status, reason, quarantined_at) VALUES (?, ?, ?, ?, ?)",
                (path, json.dumps(matches), status, reason, datetime.utcnow().isoformat())
            )

    def _safe_extract_folder_file(self, path: str) -> Tuple[str, str]:
        """Safely extract folder and filename from path."""
        try:
            if not path:
                return ("Unknown", "Unknown")
            p = Path(path)
            return (p.parent.name or "Unknown", p.name or "Unknown")
        except Exception:
            return ("Unknown", "Unknown")

    def get_quarantine(self, limit: int = 100) -> List[dict]:
        """Get list of quarantined cards."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT q.path, q.matches, q.status, q.reason, q.quarantined_at,
                       c.folder, c.file, c.name, c.creator
                FROM quarantine q
                LEFT JOIN cards c ON q.path = c.path
                ORDER BY q.id DESC LIMIT ?
            """, (limit,))
            results = []
            for row in cur.fetchall():
                folder, file = self._safe_extract_folder_file(row[0])
                results.append({
                    "path": row[0],
                    "matches": json.loads(row[1]),
                    "status": row[2],
                    "reason": row[3],
                    "quarantined_at": row[4],
                    "folder": row[5] if row[5] else folder,
                    "file": row[6] if row[6] else file,
                    "name": row[7] if row[7] else "",
                    "creator": row[8] if row[8] else "Unknown"
                })
            return results

    def get_quarantine_count(self) -> int:
        """Get count of quarantined cards."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM quarantine")
            return cur.fetchone()[0]

    def get_all_quarantine_paths(self) -> List[str]:
        """Get all quarantine card paths for bulk operations."""
        with self._cursor() as cur:
            cur.execute("SELECT path FROM quarantine")
            return [row[0] for row in cur.fetchall()]

    def index_card(self, filepath: str) -> Optional[CardEntry]:
        """Index a single card file."""
        metadata = self.extract_metadata(filepath)
        if not metadata:
            return None

        data = metadata.get("data", metadata)
        tags = data.get("tags", [])
        description = data.get("description", "")
        first_mes = data.get("first_mes", "")
        personality = data.get("personality", "")
        scenario = data.get("scenario", "")

        # Check for prohibited content and log to quarantine (NO AUTO-DELETE)
        status, matches, reason = check_prohibited_content_smart(
            tags, description, first_mes, personality, scenario
        )

        # Determine NSFW
        nsfw = check_nsfw_content(tags, description, first_mes)

        folder = Path(filepath).parent.name
        filename = Path(filepath).name

        # Calculate content hash
        content_hash = ""
        if DETECT_DUPLICATES:
            hash_content = json.dumps({
                "name": data.get("name", ""),
                "description": description,
                "first_mes": first_mes,
                "personality": data.get("personality", ""),
                "scenario": data.get("scenario", "")
            }, sort_keys=True)
            content_hash = hashlib.md5(hash_content.encode()).hexdigest()

        # Calculate image hash
        image_hash = ""
        if IMAGE_HASH_AVAILABLE:
            image_hash = self.calculate_image_hash(filepath) or ""

        # Get file modification time
        try:
            file_mtime = os.path.getmtime(filepath)
        except:
            file_mtime = 0

        # Get name and creator from metadata, fallback to parsing filename
        metadata_name = data.get("name", "").strip()
        metadata_creator = data.get("creator", "").strip()

        if not metadata_name or metadata_name.lower() in ["", "unknown", "unnamed"]:
            # Parse from filename
            parsed_name, parsed_creator = parse_name_from_filename(filename)
            card_name = parsed_name
            # Also use parsed creator if metadata creator is missing
            if not metadata_creator or metadata_creator.lower() in ["", "unknown"]:
                card_creator = parsed_creator
            else:
                card_creator = metadata_creator
        else:
            card_name = metadata_name
            card_creator = metadata_creator if metadata_creator else "Unknown"

        entry = CardEntry(
            file=filename,
            path=filepath,
            folder=folder,
            name=card_name,
            creator=card_creator,
            tags=tags,
            nsfw=nsfw,
            description_preview=description[:300] if description else "",
            first_mes_preview=first_mes[:300] if first_mes else "",
            indexed_at=datetime.utcnow().isoformat(),
            content_hash=content_hash,
            image_hash=image_hash
        )

        # Insert or update in database
        with self._cursor() as cur:
            # Check if path already exists (would be a REPLACE, not INSERT)
            cur.execute("SELECT COUNT(*) FROM cards WHERE path = ?", (entry.path,))
            exists_by_path = cur.fetchone()[0] > 0

            cur.execute("""
                INSERT OR REPLACE INTO cards
                (path, file, folder, name, creator, tags, nsfw, description_preview,
                 first_mes_preview, indexed_at, content_hash, image_hash, file_mtime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.path, entry.file, entry.folder, entry.name, entry.creator,
                json.dumps(entry.tags), int(entry.nsfw), entry.description_preview,
                entry.first_mes_preview, entry.indexed_at, entry.content_hash,
                entry.image_hash, file_mtime
            ))
            # Log rowcount to verify insert
            if cur.rowcount == 0:
                logger.warning(f"INDEX: INSERT had rowcount=0 for {filepath}")
            elif exists_by_path:
                logger.debug(f"INDEX: REPLACED existing entry at {entry.path}")
        
        # Log to quarantine for manual review if needed (NEVER auto-delete)
        if status in ["block", "quarantine"]:
            logger.warning(f"QUARANTINE: {filepath} - {status.upper()} - {reason} - Matches: {matches}")
            self.add_quarantine(filepath, list(matches), status, reason)
            # Continue indexing - card is still accessible, just flagged for review

        return entry

    async def add_card(self, filepath: str):
        """Add or update a card in the index."""
        if not filepath.lower().endswith('.png'):
            return

        entry = self.index_card(filepath)
        if entry:
            logger.info(f"Indexed: {entry.name} ({entry.file})")

    async def remove_card(self, filepath: str):
        """Remove a card from the index."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM cards WHERE path = ?", (filepath,))
            if cur.rowcount > 0:
                logger.info(f"Removed from index: {filepath}")

        # Also remove from image hash cache
        if filepath in self.image_hash_objects:
            del self.image_hash_objects[filepath]

    async def full_scan(self, directories: List[str], recursive: bool = True):
        """Perform full scan of directories."""
        logger.info(f"Starting full index scan (recursive={recursive})...")
        count = 0
        processed = 0

        # Get existing paths to detect removed files
        existing_paths = set()
        with self._cursor() as cur:
            cur.execute("SELECT path FROM cards")
            existing_paths = {row[0] for row in cur.fetchall()}

        found_paths = set()

        for directory in directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory not found: {directory}")
                continue

            if recursive:
                for root, dirs, files in os.walk(directory):
                    await asyncio.sleep(0)  # Yield to keep server responsive
                    for filename in files:
                        if filename.lower().endswith('.png'):
                            filepath = os.path.join(root, filename)
                            found_paths.add(filepath)
                            processed += 1
                            self.scan_status["progress"] = processed

                            # Check if file needs re-indexing
                            try:
                                file_mtime = os.path.getmtime(filepath)
                                stored_mtime = self.get_file_mtime(filepath)

                                if stored_mtime is not None and abs(file_mtime - stored_mtime) < 1:
                                    # File unchanged, skip
                                    count += 1
                                    continue
                            except:
                                pass

                            entry = self.index_card(filepath)
                            if entry:
                                count += 1
                                if count % 100 == 0:
                                    await asyncio.sleep(0)
                                if count % 5000 == 0:
                                    logger.info(f"Indexed {count} cards...")
            else:
                for filename in os.listdir(directory):
                    if filename.lower().endswith('.png'):
                        filepath = os.path.join(directory, filename)
                        found_paths.add(filepath)
                        processed += 1
                        self.scan_status["progress"] = processed

                        try:
                            file_mtime = os.path.getmtime(filepath)
                            stored_mtime = self.get_file_mtime(filepath)

                            if stored_mtime is not None and abs(file_mtime - stored_mtime) < 1:
                                count += 1
                                continue
                        except:
                            pass

                        entry = self.index_card(filepath)
                        if entry:
                            count += 1
                            if count % 100 == 0:
                                await asyncio.sleep(0)
                            if count % 5000 == 0:
                                logger.info(f"Indexed {count} cards...")

        # Remove cards that no longer exist on disk
        removed_paths = existing_paths - found_paths
        if removed_paths:
            logger.info(f"Removing {len(removed_paths)} cards no longer on disk...")
            with self._cursor() as cur:
                for path in removed_paths:
                    cur.execute("DELETE FROM cards WHERE path = ?", (path,))
                    if path in self.image_hash_objects:
                        del self.image_hash_objects[path]

        logger.info(f"Full scan complete. Total cards indexed: {self.get_card_count()}")

    def search(
        self,
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        nsfw: Optional[bool] = None,
        creator: Optional[str] = None,
        folder: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[CardEntry], int]:
        """Search the index with filters using FTS5."""

        conditions = []
        params = []

        # Use FTS5 for text search
        if query:
            # Escape special FTS5 characters and create search query
            safe_query = query.replace('"', '""')
            conditions.append("cards.id IN (SELECT rowid FROM cards_fts WHERE cards_fts MATCH ?)")
            # Use prefix search for partial matching
            params.append(f'"{safe_query}"*')

        # Tag filtering
        if tags:
            for tag in tags:
                conditions.append("cards.tags LIKE ?")
                params.append(f'%"{tag}"%')

        # NSFW filter
        if nsfw is not None:
            conditions.append("cards.nsfw = ?")
            params.append(int(nsfw))

        # Creator filter
        if creator:
            conditions.append("cards.creator LIKE ?")
            params.append(f'%{creator}%')

        # Folder filter
        if folder:
            conditions.append("cards.folder = ?")
            params.append(folder)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with self._cursor() as cur:
            # Get total count
            cur.execute(f"SELECT COUNT(*) FROM cards WHERE {where_clause}", params)
            total = cur.fetchone()[0]

            # Get paginated results (alphabetical by name, unnamed cards last)
            cur.execute(
                f"SELECT * FROM cards WHERE {where_clause} ORDER BY CASE WHEN name = '' OR name IS NULL THEN 1 ELSE 0 END, LOWER(name) ASC LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            results = [self._row_to_entry(row) for row in cur.fetchall()]

        return results, total

    def get_duplicates(self) -> Dict[str, List[str]]:
        """Get content hash duplicates."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT content_hash, GROUP_CONCAT(path, '|||') as paths
                FROM cards
                WHERE content_hash != ''
                GROUP BY content_hash
                HAVING COUNT(*) > 1
            """)
            return {
                row[0]: row[1].split('|||')
                for row in cur.fetchall()
            }

    def get_image_duplicates(self) -> Dict[str, List[str]]:
        """Get image hash duplicates."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT image_hash, GROUP_CONCAT(path, '|||') as paths
                FROM cards
                WHERE image_hash != ''
                GROUP BY image_hash
                HAVING COUNT(*) > 1
            """)
            return {
                row[0]: row[1].split('|||')
                for row in cur.fetchall()
            }

    def is_duplicate_ignored(self, paths: List[str]) -> bool:
        """Check if duplicate group is ignored."""
        paths_hash = hashlib.md5(json.dumps(sorted(paths)).encode()).hexdigest()
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM ignored_duplicates WHERE paths_hash = ?", (paths_hash,))
            return cur.fetchone() is not None

    def ignore_duplicate(self, paths: List[str]):
        """Mark duplicate group as ignored."""
        paths_hash = hashlib.md5(json.dumps(sorted(paths)).encode()).hexdigest()
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO ignored_duplicates (paths_hash, paths) VALUES (?, ?)",
                (paths_hash, json.dumps(paths))
            )

    def delete_card(self, path: str) -> bool:
        """Delete a card from disk and index."""
        try:
            if os.path.exists(path):
                os.remove(path)
            with self._cursor() as cur:
                cur.execute("DELETE FROM cards WHERE path = ?", (path,))
                # Also clean up quarantine records
                cur.execute("DELETE FROM quarantine WHERE path = ?", (path,))
            if path in self.image_hash_objects:
                del self.image_hash_objects[path]
            return True
        except Exception as e:
            logger.error(f"Failed to delete {path}: {e}")
            return False

    def get_stats(self) -> dict:
        """Get index statistics."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM cards WHERE nsfw = 1")
            nsfw_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT creator) FROM cards")
            unique_creators = cur.fetchone()[0]

            cur.execute("SELECT folder, COUNT(*) FROM cards GROUP BY folder")
            folders = {row[0]: row[1] for row in cur.fetchall()}

            # Top creators
            cur.execute("""
                SELECT creator, COUNT(*) as cnt FROM cards
                GROUP BY creator ORDER BY cnt DESC LIMIT 50
            """)
            top_creators = [(row[0], row[1]) for row in cur.fetchall()]

        return {
            "total_cards": total,
            "nsfw_count": nsfw_count,
            "sfw_count": total - nsfw_count,
            "unique_creators": unique_creators,
            "folders": folders,
            "top_creators": top_creators
        }

    def checkpoint(self) -> Dict[str, Any]:
        """Force a WAL checkpoint to ensure all data is written to the main database file."""
        with self._cursor() as cur:
            cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            result = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM cards")
            count = cur.fetchone()[0]
        return {
            "checkpoint_result": list(result) if result else None,
            "total_cards": count
        }

    def get_all_tags(self) -> List[Tuple[str, int]]:
        """Get all tags with counts."""
        all_tags = {}
        with self._cursor() as cur:
            cur.execute("SELECT tags FROM cards")
            for row in cur.fetchall():
                tags = json.loads(row[0]) if row[0] else []
                for tag in tags:
                    all_tags[tag] = all_tags.get(tag, 0) + 1

        return sorted(all_tags.items(), key=lambda x: x[1], reverse=True)

    def save_index(self, filepath: str = None):
        """No-op for compatibility - SQLite auto-persists."""
        logger.info("Index auto-saved (SQLite)")
        return True

    def load_index(self, filepath: str = None) -> bool:
        """Check if database has data."""
        return self.get_card_count() > 0

    # ===== IMPORT METHODS =====

    def scan_source_for_import(self, source_dir: str, recursive: bool = True,
                                progress_callback: callable = None) -> Dict[str, Any]:
        """
        Scan a source directory and categorize cards for import.
        Does NOT modify source or destination - read-only scan.

        Args:
            source_dir: Directory to scan
            recursive: Whether to scan subdirectories
            progress_callback: Optional callback(phase, current, total, details) for progress updates

        Returns dict with:
            - new_cards: list of cards that can be imported
            - duplicates: list of cards that already exist
            - prohibited: list of cards blocked by strict rules
            - quarantine: list of cards needing manual review
        """
        def update_progress(phase, current, total, **details):
            if progress_callback:
                progress_callback(phase, current, total, details)
        results = {
            "source_dir": source_dir,
            "scanned_at": datetime.utcnow().isoformat(),
            "total_files": 0,
            "new_cards": [],
            "duplicates": [],
            "prohibited": [],
            "quarantine": [],
            "errors": []
        }

        if not os.path.exists(source_dir):
            results["errors"].append(f"Directory not found: {source_dir}")
            return results

        # Get existing files - check by relative path (folder/filename) to match across different base dirs
        existing_paths = set()  # Full paths for exact match
        existing_relative = set()  # (folder, filename) for cross-directory match
        existing_content_hashes = set()
        existing_image_hashes = set()
        with self._cursor() as cur:
            cur.execute("SELECT path, folder, file FROM cards")
            for row in cur.fetchall():
                existing_paths.add(row[0])
                existing_relative.add((row[1], row[2]))  # (folder, filename)
            cur.execute("SELECT content_hash FROM cards WHERE content_hash != ''")
            existing_content_hashes = {row[0] for row in cur.fetchall()}
            cur.execute("SELECT image_hash FROM cards WHERE image_hash != ''")
            existing_image_hashes = {row[0] for row in cur.fetchall()}

        logger.info(f"Import scan: {len(existing_paths)} files already indexed")
        update_progress("indexing", 0, 0, message="Checking existing files...")

        # Scan source directory - skip files already in DB (by path OR by folder/filename)
        all_files = []
        files_to_scan = []
        skipped_existing = 0

        update_progress("discovering", 0, 0, message="Discovering files...")

        if recursive:
            for root, dirs, files in os.walk(source_dir):
                for filename in files:
                    if filename.lower().endswith('.png'):
                        filepath = os.path.join(root, filename)
                        folder = os.path.basename(root)
                        all_files.append(filepath)
                        # Skip if exact path matches OR if folder/filename combo exists
                        if filepath in existing_paths or (folder, filename) in existing_relative:
                            skipped_existing += 1
                        else:
                            files_to_scan.append(filepath)
                # Update progress during discovery
                if len(all_files) % 100 == 0:
                    update_progress("discovering", len(all_files), 0,
                                  message=f"Found {len(all_files)} files, {skipped_existing} already indexed...")
        else:
            folder = os.path.basename(source_dir)
            for filename in os.listdir(source_dir):
                if filename.lower().endswith('.png'):
                    filepath = os.path.join(source_dir, filename)
                    all_files.append(filepath)
                    if filepath in existing_paths or (folder, filename) in existing_relative:
                        skipped_existing += 1
                    else:
                        files_to_scan.append(filepath)

        results["total_files"] = len(all_files)
        results["skipped_existing"] = skipped_existing
        results["files_to_process"] = len(files_to_scan)
        skipped_duplicates = 0

        logger.info(f"Import scan: {len(all_files)} total files, {skipped_existing} already indexed, {len(files_to_scan)} to process")
        update_progress("analyzing", 0, len(files_to_scan),
                       message=f"Analyzing {len(files_to_scan)} new files...",
                       skipped_existing=skipped_existing)

        for i, filepath in enumerate(files_to_scan):
            # Update progress every file
            if i % 10 == 0 or i == len(files_to_scan) - 1:
                update_progress("analyzing", i + 1, len(files_to_scan),
                              current_file=Path(filepath).name,
                              new_cards=len(results["new_cards"]),
                              skipped_duplicates=skipped_duplicates,
                              prohibited=len(results["prohibited"]),
                              quarantine=len(results["quarantine"]),
                              errors=len(results["errors"]))

            try:
                card_info = self._analyze_card_for_import(
                    filepath,
                    existing_content_hashes,
                    existing_image_hashes
                )

                if card_info["status"] == "new":
                    results["new_cards"].append(card_info)
                elif card_info["status"] == "duplicate":
                    # Silently skip duplicates - user doesn't want to see them
                    skipped_duplicates += 1
                elif card_info["status"] == "prohibited":
                    results["prohibited"].append(card_info)
                elif card_info["status"] == "quarantine":
                    results["quarantine"].append(card_info)
                    # Also save to quarantine table
                    self._add_to_quarantine(card_info)

            except Exception as e:
                results["errors"].append(f"{filepath}: {str(e)}")

        results["skipped_duplicates"] = skipped_duplicates
        update_progress("complete", len(files_to_scan), len(files_to_scan),
                       new_cards=len(results["new_cards"]),
                       skipped_duplicates=skipped_duplicates,
                       prohibited=len(results["prohibited"]),
                       quarantine=len(results["quarantine"]),
                       errors=len(results["errors"]))

        # Cache results
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO import_scan_cache
                (source_dir, scanned_at, total_files, new_cards, duplicates, prohibited, quarantined, results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source_dir,
                results["scanned_at"],
                results["total_files"],
                len(results["new_cards"]),
                len(results["duplicates"]),
                len(results["prohibited"]),
                len(results["quarantine"]),
                json.dumps(results)
            ))

        return results

    def _analyze_card_for_import(self, filepath: str,
                                  existing_content_hashes: set,
                                  existing_image_hashes: set) -> Dict[str, Any]:
        """Analyze a single card for import eligibility."""
        metadata = self.extract_metadata(filepath)

        card_info = {
            "path": filepath,
            "file": Path(filepath).name,
            "folder": Path(filepath).parent.name,
            "status": "new",
            "reason": "",
            "matches": []
        }

        if not metadata:
            card_info["status"] = "error"
            card_info["reason"] = "No valid metadata"
            return card_info

        data = metadata.get("data", metadata)
        tags = data.get("tags", [])
        description = data.get("description", "")
        first_mes = data.get("first_mes", "")
        personality = data.get("personality", "")
        scenario = data.get("scenario", "")

        card_info["name"] = data.get("name", card_info["file"].replace(".png", ""))
        card_info["creator"] = data.get("creator", "Unknown")
        card_info["tags"] = tags
        card_info["nsfw"] = check_nsfw_content(tags, description, first_mes)

        # Calculate content hash
        hash_content = json.dumps({
            "name": data.get("name", ""),
            "description": description,
            "first_mes": first_mes,
            "personality": personality,
            "scenario": scenario
        }, sort_keys=True)
        content_hash = hashlib.md5(hash_content.encode()).hexdigest()
        card_info["content_hash"] = content_hash

        # Check for content duplicate
        if content_hash in existing_content_hashes:
            card_info["status"] = "duplicate"
            card_info["reason"] = "Content hash already exists"
            return card_info

        # Calculate image hash
        if IMAGE_HASH_AVAILABLE:
            try:
                with Image.open(filepath) as img:
                    phash = imagehash.dhash(img, hash_size=12)
                    image_hash = str(phash)
                    card_info["image_hash"] = image_hash

                    if image_hash in existing_image_hashes:
                        card_info["status"] = "duplicate"
                        card_info["reason"] = "Image hash already exists"
                        return card_info
            except Exception as e:
                card_info["image_hash"] = ""

        # Smart prohibited content check
        status, matches, reason = check_prohibited_content_smart(
            tags, description, first_mes, personality, scenario
        )

        if status == "block":
            card_info["status"] = "prohibited"
            card_info["reason"] = reason
            card_info["matches"] = list(matches)
        elif status == "quarantine":
            card_info["status"] = "quarantine"
            card_info["reason"] = reason
            card_info["matches"] = list(matches)
        # else: status remains "new"

        return card_info

    def _add_to_quarantine(self, card_info: Dict[str, Any]):
        """Add a card to the quarantine table for manual review."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO import_quarantine
                (source_path, name, creator, status, reason, matches, scanned_at)
                VALUES (?, ?, ?, 'pending', ?, ?, ?)
            """, (
                card_info["path"],
                card_info.get("name", ""),
                card_info.get("creator", "Unknown"),
                card_info.get("reason", ""),
                json.dumps(card_info.get("matches", [])),
                datetime.utcnow().isoformat()
            ))

    def get_quarantine_list(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Get cards in quarantine."""
        with self._cursor() as cur:
            if status:
                cur.execute(
                    "SELECT * FROM import_quarantine WHERE status = ? ORDER BY scanned_at DESC LIMIT ?",
                    (status, limit)
                )
            else:
                cur.execute(
                    "SELECT * FROM import_quarantine ORDER BY scanned_at DESC LIMIT ?",
                    (limit,)
                )
            return [dict(row) for row in cur.fetchall()]

    def review_quarantine_card(self, source_path: str, decision: str) -> bool:
        """
        Review a quarantined card.
        decision: "approve" | "reject"
        """
        with self._cursor() as cur:
            cur.execute("""
                UPDATE import_quarantine
                SET status = ?, reviewed_at = ?, decision = ?
                WHERE source_path = ?
            """, (
                "reviewed",
                datetime.utcnow().isoformat(),
                decision,
                source_path
            ))
            return cur.rowcount > 0

    def execute_import(self, cards_to_import: List[str], destination_folder: str = None) -> Dict[str, Any]:
        """
        Actually import the specified cards.
        cards_to_import: list of source file paths
        destination_folder: subfolder name in CARD_DIRS[0] (default: source folder name)
        """
        results = {
            "imported": [],
            "failed": [],
            "skipped": []
        }

        if not CARD_DIRS or not CARD_DIRS[0]:
            results["failed"].append({"error": "No destination directory configured"})
            return results

        base_dir = CARD_DIRS[0]

        # Log count before import
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            count_before = cur.fetchone()[0]
        logger.info(f"IMPORT: Starting import of {len(cards_to_import)} cards. Current DB count: {count_before}")
        logger.info(f"IMPORT: Destination base directory: {base_dir}")

        for source_path in cards_to_import:
            try:
                if not os.path.exists(source_path):
                    results["skipped"].append({
                        "path": source_path,
                        "reason": "Source file not found"
                    })
                    continue

                # Determine destination
                if destination_folder:
                    dest_folder = destination_folder
                else:
                    dest_folder = Path(source_path).parent.name

                # Sanitize folder name
                safe_folder = "".join(c for c in dest_folder if c.isalnum() or c in " -_").strip() or "Imported"
                dest_dir = os.path.join(base_dir, safe_folder)
                os.makedirs(dest_dir, exist_ok=True)

                # Copy file
                dest_path = os.path.join(dest_dir, Path(source_path).name)

                # Handle name collision
                if os.path.exists(dest_path):
                    base, ext = os.path.splitext(Path(source_path).name)
                    counter = 1
                    while os.path.exists(dest_path):
                        dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
                        counter += 1

                shutil.copy2(source_path, dest_path)

                # Verify copy succeeded
                if not os.path.exists(dest_path):
                    logger.error(f"IMPORT: Copy failed - file doesn't exist at {dest_path}")
                    results["failed"].append({
                        "path": source_path,
                        "reason": "Copy failed - destination file not found"
                    })
                    continue

                # Index the new card
                entry = self.index_card(dest_path, delete_prohibited=False)
                if entry:
                    results["imported"].append({
                        "source": source_path,
                        "destination": dest_path,
                        "name": entry.name
                    })
                    # Log every 100th import for progress tracking
                    if len(results["imported"]) % 100 == 0:
                        logger.info(f"IMPORT: Progress - {len(results['imported'])} cards indexed")
                else:
                    logger.warning(f"IMPORT: index_card returned None for {dest_path}")
                    results["failed"].append({
                        "path": source_path,
                        "reason": "Failed to index after copy"
                    })

            except Exception as e:
                logger.error(f"IMPORT: Exception importing {source_path}: {e}")
                results["failed"].append({
                    "path": source_path,
                    "reason": str(e)
                })

        # Log count after import and verify
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cards")
            count_after = cur.fetchone()[0]

        logger.info(f"IMPORT: Complete. Imported: {len(results['imported'])}, Failed: {len(results['failed'])}, Skipped: {len(results['skipped'])}")
        logger.info(f"IMPORT: DB count before: {count_before}, after: {count_after}, difference: {count_after - count_before}")

        if len(results["imported"]) > 0 and count_after == count_before:
            logger.error("IMPORT: WARNING - Cards reported as imported but DB count unchanged!")
            # Check if sample cards actually exist in DB
            sample_paths = [r["destination"] for r in results["imported"][:5]]
            for path in sample_paths:
                cur.execute("SELECT COUNT(*) FROM cards WHERE path = ?", (path,))
                exists = cur.fetchone()[0]
                logger.error(f"IMPORT: Verify - {path} exists in DB: {exists}")

        return results

    def get_last_import_scan(self, source_dir: str = None) -> Optional[Dict]:
        """Get the last import scan results."""
        with self._cursor() as cur:
            if source_dir:
                cur.execute(
                    "SELECT results FROM import_scan_cache WHERE source_dir = ? ORDER BY scanned_at DESC LIMIT 1",
                    (source_dir,)
                )
            else:
                cur.execute(
                    "SELECT results FROM import_scan_cache ORDER BY scanned_at DESC LIMIT 1"
                )
            row = cur.fetchone()
            return json.loads(row[0]) if row else None

    # ===== LOREBOOK METHODS =====

    def scan_lorebooks(self, lorebook_dir: str, recursive: bool = True) -> Dict[str, Any]:
        """
        Scan a directory for lorebook files and index them.
        """
        results = {
            "source_dir": lorebook_dir,
            "scanned_at": datetime.utcnow().isoformat(),
            "total_files": 0,
            "indexed": 0,
            "skipped": 0,
            "errors": []
        }

        if not os.path.exists(lorebook_dir):
            results["errors"].append(f"Directory not found: {lorebook_dir}")
            return results

        # Get existing lorebook paths to skip
        existing_paths = set()
        with self._cursor() as cur:
            cur.execute("SELECT file_path FROM lorebooks")
            existing_paths = {row[0] for row in cur.fetchall()}

        logger.info(f"Lorebook scan: {len(existing_paths)} lorebooks already indexed")

        # Find all sillytavern lorebook files
        files_to_scan = []
        if recursive:
            for root, dirs, files in os.walk(lorebook_dir):
                for filename in files:
                    if filename.endswith('.lorebook_sillytavern.json'):
                        filepath = os.path.join(root, filename)
                        if filepath not in existing_paths:
                            files_to_scan.append(filepath)
                        else:
                            results["skipped"] += 1
        else:
            for filename in os.listdir(lorebook_dir):
                if filename.endswith('.lorebook_sillytavern.json'):
                    filepath = os.path.join(lorebook_dir, filename)
                    if filepath not in existing_paths:
                        files_to_scan.append(filepath)
                    else:
                        results["skipped"] += 1

        results["total_files"] = len(files_to_scan) + results["skipped"]
        logger.info(f"Lorebook scan: {len(files_to_scan)} new lorebooks to index")

        for filepath in files_to_scan:
            try:
                lorebook_data = self._parse_lorebook(filepath)
                if lorebook_data:
                    self._index_lorebook(lorebook_data)
                    results["indexed"] += 1
            except Exception as e:
                results["errors"].append(f"{filepath}: {str(e)}")
                logger.error(f"Error indexing lorebook {filepath}: {e}")

        logger.info(f"Lorebook scan complete: {results['indexed']} indexed, {results['skipped']} skipped")
        return results

    def _parse_lorebook(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse a SillyTavern lorebook file and extract metadata."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            filename = Path(filepath).name

            # Extract basic info from metadata
            metadata_name = data.get("name", "").strip()
            description = data.get("description", "")
            entries = data.get("entries", {})

            # Lorebook extensions
            lorebook_extensions = ['.lorebook_sillytavern.json', '.lorebook.json', '.json']

            # Check if name is empty/generic and needs to be parsed from filename
            stem = Path(filepath).stem.split('.')[0]
            if not metadata_name or metadata_name.lower() in ["", "unknown", "unnamed"] or metadata_name == stem:
                parsed_name, parsed_creator = parse_name_from_filename(filename, lorebook_extensions)
                name = parsed_name if parsed_name else stem
            else:
                name = metadata_name

            # Extract keywords from all entries
            keywords = set()
            for entry in entries.values():
                keys = entry.get("keys", entry.get("key", []))
                if isinstance(keys, list):
                    keywords.update(k.lower() for k in keys if k)

            # Get chub metadata if available
            chub_ext = data.get("extensions", {}).get("chub", {})
            chub_id = chub_ext.get("id", 0)

            # Get creator - try multiple sources
            creator = "Unknown"

            # 1. Try folder structure (creator/lorebook-name/file.json)
            path_parts = Path(filepath).parts
            if len(path_parts) >= 3:
                for i, part in enumerate(path_parts):
                    if part == "lorebooks" and i + 1 < len(path_parts):
                        creator = path_parts[i + 1]
                        break

            # 2. If still unknown, try to get from filename parsing
            if creator == "Unknown":
                _, parsed_creator = parse_name_from_filename(filename, lorebook_extensions)
                if parsed_creator and parsed_creator != "Unknown":
                    creator = parsed_creator

            # Try to get metadata from node.json in chub folder
            topics = []
            star_count = 0
            token_count = data.get("token_budget", 0)
            nsfw = False

            chub_dir = Path(filepath).parent / "chub"
            node_files = list(chub_dir.glob("*.node.json")) if chub_dir.exists() else []
            if node_files:
                try:
                    with open(node_files[0], 'r', encoding='utf-8') as f:
                        node_data = json.load(f)
                        topics = node_data.get("topics", [])
                        star_count = node_data.get("starCount", 0)
                        token_count = node_data.get("nTokens", token_count)
                        nsfw = "NSFW" in topics
                except:
                    pass

            # Calculate content hash
            content_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()

            return {
                "file_path": filepath,
                "file": Path(filepath).name,
                "folder": Path(filepath).parent.name,
                "name": name,
                "creator": creator,
                "description": description,
                "topics": topics,
                "entry_count": len(entries),
                "token_count": token_count,
                "keywords": ", ".join(sorted(keywords)),
                "star_count": star_count,
                "chub_id": chub_id,
                "nsfw": nsfw,
                "content_hash": content_hash
            }
        except Exception as e:
            logger.error(f"Error parsing lorebook {filepath}: {e}")
            return None

    def write_lorebook_metadata(self, filepath: str, name: str = None, creator: str = None) -> bool:
        """Update lorebook JSON file with new name/creator."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            updated = False
            if name:
                data["name"] = name
                updated = True

            # For creator, we could add it to extensions if needed
            # SillyTavern lorebooks don't have a standard creator field
            # But we can add it to extensions.chub or a custom field

            if updated:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                return True

            return False
        except Exception as e:
            logger.error(f"Error writing lorebook metadata to {filepath}: {e}")
            return False

    def _index_lorebook(self, lorebook_data: Dict[str, Any]) -> bool:
        """Add a lorebook to the database."""
        try:
            with self._cursor() as cur:
                cur.execute("""
                    INSERT OR REPLACE INTO lorebooks
                    (file_path, file, folder, name, creator, description, topics, entry_count,
                     token_count, keywords, star_count, chub_id, nsfw, indexed_at, content_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    lorebook_data["file_path"],
                    lorebook_data["file"],
                    lorebook_data["folder"],
                    lorebook_data["name"],
                    lorebook_data["creator"],
                    lorebook_data["description"],
                    json.dumps(lorebook_data["topics"]),
                    lorebook_data["entry_count"],
                    lorebook_data["token_count"],
                    lorebook_data["keywords"],
                    lorebook_data["star_count"],
                    lorebook_data["chub_id"],
                    1 if lorebook_data["nsfw"] else 0,
                    datetime.utcnow().isoformat(),
                    lorebook_data["content_hash"]
                ))
            return True
        except Exception as e:
            logger.error(f"Error indexing lorebook: {e}")
            return False

    def search_lorebooks(self, query: str = None, topics: List[str] = None,
                         creator: str = None, nsfw: bool = None,
                         limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """Search lorebooks with filters. Returns (results, total_count)."""
        with self._cursor() as cur:
            if query:
                # FTS search
                base_sql = """
                    SELECT l.* FROM lorebooks l
                    JOIN lorebooks_fts fts ON l.id = fts.rowid
                    WHERE lorebooks_fts MATCH ?
                """
                count_sql = """
                    SELECT COUNT(*) FROM lorebooks l
                    JOIN lorebooks_fts fts ON l.id = fts.rowid
                    WHERE lorebooks_fts MATCH ?
                """
                params = [query]
            else:
                base_sql = "SELECT * FROM lorebooks WHERE 1=1"
                count_sql = "SELECT COUNT(*) FROM lorebooks WHERE 1=1"
                params = []

            filter_sql = ""
            if topics:
                for topic in topics:
                    filter_sql += " AND topics LIKE ?"
                    params.append(f'%"{topic}"%')

            if creator:
                filter_sql += " AND creator = ?"
                params.append(creator)

            if nsfw is not None:
                filter_sql += " AND nsfw = ?"
                params.append(1 if nsfw else 0)

            # Get total count
            cur.execute(count_sql + filter_sql, params)
            total = cur.fetchone()[0]

            # Get paginated results
            sql = base_sql + filter_sql + " ORDER BY CASE WHEN name = '' OR name IS NULL THEN 1 ELSE 0 END, LOWER(name) ASC LIMIT ? OFFSET ?"
            cur.execute(sql, params + [limit, offset])
            columns = [desc[0] for desc in cur.description]
            results = [dict(zip(columns, row)) for row in cur.fetchall()]

            return results, total

    def get_lorebook(self, lorebook_id: int) -> Optional[Dict[str, Any]]:
        """Get a lorebook by ID with full content."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM lorebooks WHERE id = ?", (lorebook_id,))
            row = cur.fetchone()
            if not row:
                return None

            columns = [desc[0] for desc in cur.description]
            lorebook = dict(zip(columns, row))

            # Load full content from file
            try:
                with open(lorebook["file_path"], 'r', encoding='utf-8') as f:
                    lorebook["content"] = json.load(f)
            except:
                lorebook["content"] = None

            return lorebook

    def get_lorebook_by_path(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get a lorebook by file path."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM lorebooks WHERE file_path = ?", (file_path,))
            row = cur.fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cur.description]
            return dict(zip(columns, row))

    def get_lorebook_count(self) -> int:
        """Get total number of indexed lorebooks."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM lorebooks")
            return cur.fetchone()[0]

    def get_lorebook_topics(self) -> List[Dict[str, Any]]:
        """Get all topics with counts."""
        with self._cursor() as cur:
            cur.execute("SELECT topics FROM lorebooks")
            topic_counts = {}
            for row in cur.fetchall():
                try:
                    topics = json.loads(row[0])
                    for topic in topics:
                        topic_counts[topic] = topic_counts.get(topic, 0) + 1
                except:
                    pass
            return [{"name": k, "count": v} for k, v in sorted(topic_counts.items(), key=lambda x: -x[1])]

    def get_lorebook_stats(self) -> Dict[str, Any]:
        """Get lorebook statistics."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM lorebooks")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM lorebooks WHERE nsfw = 1")
            nsfw_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT creator) FROM lorebooks")
            creator_count = cur.fetchone()[0]

            cur.execute("SELECT SUM(entry_count) FROM lorebooks")
            total_entries = cur.fetchone()[0] or 0

            return {
                "total_lorebooks": total,
                "nsfw_count": nsfw_count,
                "sfw_count": total - nsfw_count,
                "creator_count": creator_count,
                "total_entries": total_entries
            }


# File watcher handler
class CardFileHandler(FileSystemEventHandler):
    def __init__(self, index: CardIndexDB, loop: asyncio.AbstractEventLoop):
        self.index = index
        self.loop = loop

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith('.png'):
            asyncio.run_coroutine_threadsafe(
                self.index.add_card(event.src_path), self.loop
            )

    def on_deleted(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.index.remove_card(event.src_path), self.loop
            )

    def on_moved(self, event):
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.index.remove_card(event.src_path), self.loop
            )
            if event.dest_path.lower().endswith('.png'):
                asyncio.run_coroutine_threadsafe(
                    self.index.add_card(event.dest_path), self.loop
                )


# FastAPI app
app = FastAPI(title="Character Card Index", version="2.0.0-sqlite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

index = CardIndexDB()
observer = None


# Watcher status for dashboard
watcher_status = {"state": "disabled", "directories": 0, "ready": False}

def setup_watcher_background(loop):
    """Set up file watcher in background thread using polling (no inotify limits)."""
    global observer, watcher_status

    try:
        watcher_status["state"] = "initializing"
        logger.info("File watcher initializing (polling mode)...")

        handler = CardFileHandler(index, loop)
        # PollingObserver checks for changes every few seconds
        # No inotify limits - works with any number of directories
        observer = PollingObserver(timeout=10)  # Check every 10 seconds

        dir_count = 0
        for directory in CARD_DIRS:
            if os.path.exists(directory):
                observer.schedule(handler, directory, recursive=RECURSIVE)
                dir_count += 1
                logger.info(f"Watching directory: {directory} (recursive={RECURSIVE}, polling mode)")

        watcher_status["directories"] = dir_count
        observer.start()
        watcher_status["state"] = "active"
        watcher_status["ready"] = True
        logger.info(f"File watcher ready - polling {dir_count} directories every 10 seconds")

    except Exception as e:
        watcher_status["state"] = f"error: {e}"
        logger.error(f"File watcher setup failed: {e}")


@app.on_event("startup")
async def startup():
    global observer

    card_count = index.get_card_count()

    # Start file watcher in background thread (non-blocking)
    if WATCH_FILES:
        loop = asyncio.get_event_loop()
        # Run watcher setup in a thread so it doesn't block startup
        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        executor.submit(setup_watcher_background, loop)
        watcher_msg = "file watcher starting in background"
    else:
        observer = None
        watcher_status["state"] = "disabled"
        watcher_msg = "file watcher disabled"
        logger.info("File watching disabled (CARD_WATCH_FILES=false)")

    # Only scan on startup if database is empty OR rescan is explicitly enabled
    if card_count > 0 and not RESCAN_ON_STARTUP:
        logger.info(f"Server ready with {card_count} cards in database ({watcher_msg})")
        index.scan_status["last_scan"] = "cached"
    else:
        if card_count > 0:
            logger.info(f"Server ready with {card_count} cards, starting background rescan (CARD_RESCAN_STARTUP=true)...")
        else:
            logger.info("Empty database, performing initial scan...")
        asyncio.create_task(background_scan())


async def background_scan():
    """Run full scan in background."""
    await asyncio.sleep(0.1)

    try:
        index.scan_status["running"] = True
        index.scan_status["progress"] = 0
        index.scan_status["total"] = 0

        logger.info("Background scan starting...")
        await index.full_scan(CARD_DIRS, recursive=RECURSIVE)

        index.scan_status["running"] = False
        index.scan_status["last_scan"] = datetime.utcnow().isoformat()

    except Exception as e:
        logger.error(f"Background scan error: {e}")
        index.scan_status["running"] = False


@app.on_event("shutdown")
async def shutdown():
    if observer:
        observer.stop()
        observer.join()


# Dashboard HTML (same as original)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CardVault Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e; color: #eee; line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px; margin-bottom: 30px; border-radius: 12px;
        }
        header h1 { font-size: 2rem; margin-bottom: 10px; }
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }
        .stat-card {
            background: #16213e; padding: 20px; border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .stat-card h3 { font-size: 0.9rem; color: #888; margin-bottom: 5px; }
        .stat-card .value { font-size: 2rem; font-weight: bold; color: #667eea; }
        .stat-card.warning { border-left-color: #f39c12; }
        .stat-card.warning .value { color: #f39c12; }
        .stat-card.danger { border-left-color: #e74c3c; }
        .stat-card.danger .value { color: #e74c3c; }
        .stat-card.success { border-left-color: #2ecc71; }
        .stat-card.success .value { color: #2ecc71; }
        .stat-mini {
            background: #1a1a2e; padding: 8px 15px; border-radius: 8px; font-size: 0.9rem;
        }
        .stat-mini strong { color: #667eea; }
        .lorebook-card {
            background: #0f3460; border-radius: 10px; position: relative;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .lorebook-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.3);
        }
        .section {
            background: #16213e; border-radius: 12px; padding: 25px;
            margin-bottom: 25px;
        }
        .section h2 {
            font-size: 1.3rem; margin-bottom: 20px; padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab {
            padding: 10px 20px; background: #0f3460; border: none;
            color: #fff; border-radius: 8px; cursor: pointer; transition: all 0.2s;
        }
        .tab:hover { background: #1a4a7a; }
        .tab.active { background: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #888; font-weight: 500; font-size: 0.85rem; text-transform: uppercase; }
        tr:hover { background: #1a3a5c; }
        .tag {
            display: inline-block; padding: 3px 8px; background: #0f3460;
            border-radius: 4px; font-size: 0.8rem; margin: 2px;
        }
        .tag.blocked { background: #e74c3c; }
        .btn {
            padding: 10px 20px; border: none; border-radius: 8px;
            cursor: pointer; font-weight: 500; transition: all 0.2s;
        }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5a6fd6; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-danger:hover { background: #c0392b; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .search-box { display: flex; gap: 10px; margin-bottom: 20px; }
        .search-box input {
            flex: 1; padding: 12px; background: #0f3460; border: 1px solid #333;
            border-radius: 8px; color: #fff; font-size: 1rem;
        }
        .search-box input:focus { outline: none; border-color: #667eea; }
        .card-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 15px;
        }
        .card {
            background: #0f3460; border-radius: 10px; overflow: hidden;
            cursor: pointer; transition: transform 0.2s;
        }
        .card:hover { transform: translateY(-5px); }
        .card img { width: 100%; aspect-ratio: 1; object-fit: cover; }
        .card-info { padding: 12px; }
        .card-info h4 { font-size: 0.95rem; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .card-info p { font-size: 0.8rem; color: #888; }
        .nsfw-badge {
            position: absolute; top: 8px; right: 8px; background: #e74c3c;
            padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
        }
        .dupe-group {
            background: #0f3460; padding: 15px; border-radius: 8px; margin-bottom: 15px;
            position: relative;
        }
        .dupe-group h4 { margin-bottom: 10px; color: #f39c12; }
        .dupe-group .ignore-btn {
            position: absolute; top: 10px; right: 10px; background: #27ae60;
            border: none; color: white; padding: 5px 12px; border-radius: 6px;
            cursor: pointer; font-size: 0.85rem;
        }
        .dupe-group .ignore-btn:hover { background: #2ecc71; }
        .dupe-group .type-badge {
            display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; margin-left: 10px;
        }
        .dupe-group .type-badge.content { background: #667eea; }
        .dupe-group .type-badge.image { background: #e74c3c; }
        .dupe-cards { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
        .dupe-card {
            background: #1a1a2e; border-radius: 8px; overflow: hidden;
            width: 140px; position: relative;
        }
        .dupe-card img { width: 100%; aspect-ratio: 1; object-fit: cover; cursor: pointer; }
        .dupe-card .info { padding: 8px; font-size: 0.8rem; }
        .dupe-card .info h5 { margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .dupe-card .info p { margin: 2px 0 0; color: #888; font-size: 0.75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .dupe-card .keep-badge {
            position: absolute; top: 5px; left: 5px; background: #2ecc71;
            padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
        }
        .dupe-card .delete-btn {
            position: absolute; top: 5px; right: 5px; background: #e74c3c;
            border: none; color: white; width: 24px; height: 24px; border-radius: 50%;
            cursor: pointer; font-size: 0.9rem; display: flex; align-items: center;
            justify-content: center; opacity: 0.8; transition: opacity 0.2s;
        }
        .dupe-card .delete-btn:hover { opacity: 1; }
        .dupe-card.deleted { opacity: 0.3; pointer-events: none; }
        .dupe-card.deleted::after {
            content: 'DELETED'; position: absolute; top: 50%; left: 50%;
            transform: translate(-50%, -50%); background: #e74c3c; padding: 5px 10px;
            border-radius: 4px; font-weight: bold;
        }
        .dupe-path {
            font-family: monospace; font-size: 0.75rem; padding: 3px 8px;
            background: #1a1a2e; margin: 3px 0; border-radius: 4px; color: #666;
        }
        .loading { text-align: center; padding: 40px; color: #888; }
        .empty { text-align: center; padding: 40px; color: #666; }
        .actions { display: flex; gap: 10px; margin-top: 15px; }
        #toast {
            position: fixed; bottom: 20px; right: 20px; background: #2ecc71;
            padding: 15px 25px; border-radius: 8px; display: none; z-index: 1000;
        }
        #toast.error { background: #e74c3c; }
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8); display: none; z-index: 2000;
            justify-content: center; align-items: center; padding: 20px;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: #16213e; border-radius: 16px; max-width: 900px;
            width: 100%; max-height: 90vh; overflow-y: auto; position: relative;
        }
        .modal-close {
            position: absolute; top: 15px; right: 15px; background: #e74c3c;
            border: none; color: white; width: 36px; height: 36px; border-radius: 50%;
            cursor: pointer; font-size: 1.2rem; z-index: 10;
        }
        .modal-header { display: flex; gap: 20px; padding: 25px; border-bottom: 1px solid #333; }
        .modal-header img {
            width: 200px; height: 200px; object-fit: cover; border-radius: 12px;
            flex-shrink: 0;
        }
        .modal-header-info { flex: 1; }
        .modal-header-info h2 { font-size: 1.5rem; margin-bottom: 8px; }
        .modal-header-info .creator { color: #2ecc71; margin-bottom: 12px; }
        .modal-header-info .meta { color: #888; font-size: 0.9rem; }
        .modal-body { padding: 25px; }
        .modal-section { margin-bottom: 20px; }
        .modal-section h3 {
            font-size: 0.9rem; color: #888; text-transform: uppercase;
            margin-bottom: 8px; letter-spacing: 1px;
        }
        .modal-section-content {
            background: #0f3460; padding: 15px; border-radius: 8px;
            white-space: pre-wrap; font-size: 0.95rem; line-height: 1.6;
            max-height: 300px; overflow-y: auto;
        }
        .modal-tags { display: flex; flex-wrap: wrap; gap: 8px; }
        .modal-tags .tag { background: #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CardVault Dashboard</h1>
            <p>Character Card Index Server v2.0.0-sqlite</p>
            <div style="margin-top:15px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <button class="btn btn-primary" onclick="triggerRescan()" id="rescan-btn">Rescan Index</button>
                <button class="btn btn-primary" onclick="triggerNextcloudScan()" id="nextcloud-btn">Refresh Nextcloud</button>
                <span id="scan-status" style="font-size:0.9rem;"></span>
            </div>
        </header>

        <div class="stats-grid" id="stats-grid">
            <div class="stat-card"><h3>Loading...</h3><div class="value">-</div></div>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="search">Search Cards</button>
            <button class="tab" data-tab="lorebooks">Lorebooks</button>
            <button class="tab" data-tab="duplicates">Duplicates</button>
            <button class="tab" data-tab="import">Import</button>
            <button class="tab" data-tab="quarantine">Quarantine</button>
            <button class="tab" data-tab="tags">Top Tags</button>
        </div>

        <div id="search" class="tab-content active">
            <div class="section">
                <h2>Search Cards</h2>
                <div class="search-box">
                    <input type="text" id="search-input" placeholder="Search by name, description, or creator...">
                    <button class="btn btn-primary" onclick="searchCards(1)">Search</button>
                </div>
                <div class="filter-row" style="display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center;">
                    <div style="display:flex;align-items:center;gap:5px;">
                        <label style="color:#888;font-size:0.9rem;">Tag:</label>
                        <select id="tag-filter" onchange="searchCards(1)" style="padding:8px 12px;background:#0f3460;border:1px solid #333;border-radius:6px;color:#fff;min-width:150px;">
                            <option value="">All Tags</option>
                        </select>
                    </div>
                    <div style="display:flex;align-items:center;gap:5px;">
                        <label style="color:#888;font-size:0.9rem;">NSFW:</label>
                        <select id="nsfw-filter" onchange="searchCards(1)" style="padding:8px 12px;background:#0f3460;border:1px solid #333;border-radius:6px;color:#fff;">
                            <option value="">All</option>
                            <option value="false">SFW Only</option>
                            <option value="true">NSFW Only</option>
                        </select>
                    </div>
                    <div id="active-filters" style="display:flex;gap:5px;flex-wrap:wrap;"></div>
                </div>
                <div id="search-results" class="card-grid"></div>
                <div id="search-loading" class="loading" style="display:none;">Searching...</div>
                <div id="search-pagination" class="pagination" style="display:none;margin-top:20px;text-align:center;">
                    <button class="btn" id="prev-page" onclick="prevPage()">&lt; Previous</button>
                    <span id="page-info" style="margin:0 20px;color:#888;"></span>
                    <button class="btn" id="next-page" onclick="nextPage()">Next &gt;</button>
                    <div style="margin-top:10px;">
                        <input type="number" id="goto-page" min="1" style="width:60px;padding:8px;background:#0f3460;border:1px solid #333;border-radius:4px;color:#fff;text-align:center;">
                        <button class="btn btn-primary" onclick="goToPage()" style="margin-left:5px;">Go</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="lorebooks" class="tab-content">
            <div class="section">
                <h2>Lorebooks</h2>
                <div class="lorebook-stats" style="display:flex;gap:15px;margin-bottom:20px;flex-wrap:wrap;">
                    <div class="stat-mini"><strong id="lb-total">0</strong> Total</div>
                    <div class="stat-mini"><strong id="lb-nsfw">0</strong> NSFW</div>
                    <div class="stat-mini"><strong id="lb-creators">0</strong> Creators</div>
                    <div class="stat-mini"><strong id="lb-entries">0</strong> Entries</div>
                </div>

                <div class="search-box" style="margin-bottom:15px;">
                    <input type="text" id="lb-search-input" placeholder="Search lorebooks by name, keywords, description...">
                    <button class="btn btn-primary" onclick="searchLorebooks(1)">Search</button>
                    <button class="btn" onclick="searchLorebooks(1)" style="margin-left:5px;">Show All</button>
                </div>

                <div class="filter-row" style="display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center;">
                    <div style="display:flex;align-items:center;gap:5px;">
                        <label style="color:#888;font-size:0.9rem;">Topic:</label>
                        <select id="lb-topic-filter" onchange="searchLorebooks(1)" style="padding:8px 12px;background:#0f3460;border:1px solid #333;border-radius:6px;color:#fff;min-width:150px;">
                            <option value="">All Topics</option>
                        </select>
                    </div>
                    <div style="display:flex;align-items:center;gap:5px;">
                        <label style="color:#888;font-size:0.9rem;">NSFW:</label>
                        <select id="lb-nsfw-filter" onchange="searchLorebooks(1)" style="padding:8px 12px;background:#0f3460;border:1px solid #333;border-radius:6px;color:#fff;">
                            <option value="">All</option>
                            <option value="false">SFW Only</option>
                            <option value="true">NSFW Only</option>
                        </select>
                    </div>
                    <div id="lb-active-filters" style="display:flex;gap:5px;flex-wrap:wrap;"></div>
                </div>

                <div class="actions" style="margin-bottom:20px;display:flex;gap:10px;flex-wrap:wrap;">
                    <button class="btn btn-primary" onclick="rescanLorebooks()">Rescan Configured Dirs</button>
                    <button class="btn btn-danger" onclick="clearLorebooks()">Clear Index</button>
                    <span id="lb-config-dirs" style="color:#888;font-size:0.85rem;align-self:center;"></span>
                </div>

                <details style="margin-bottom:20px;">
                    <summary style="cursor:pointer;color:#667eea;">Scan Custom Directory</summary>
                    <div class="scan-box" style="background:#1a1a2e;padding:15px;border-radius:8px;margin-top:10px;">
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="text" id="lb-scan-dir" placeholder="/path/to/lorebooks" style="flex:1;">
                            <label style="color:#888;"><input type="checkbox" id="lb-scan-recursive" checked> Recursive</label>
                            <button class="btn btn-primary" onclick="scanLorebooks()">Scan</button>
                        </div>
                    </div>
                </details>

                <div id="lb-scan-status" style="margin-bottom:15px;color:#888;"></div>
                <div id="lb-results" class="card-grid"></div>
                <div id="lb-loading" class="loading" style="display:none;">Loading lorebooks...</div>
                <div id="lb-pagination" class="pagination" style="display:none;margin-top:20px;text-align:center;">
                    <button class="btn" id="lb-prev-page" onclick="lbPrevPage()">&lt; Previous</button>
                    <span id="lb-page-info" style="margin:0 20px;color:#888;"></span>
                    <button class="btn" id="lb-next-page" onclick="lbNextPage()">Next &gt;</button>
                    <div style="margin-top:10px;">
                        <input type="number" id="lb-goto-page" min="1" style="width:60px;padding:8px;background:#0f3460;border:1px solid #333;border-radius:4px;color:#fff;text-align:center;">
                        <button class="btn btn-primary" onclick="lbGoToPage()" style="margin-left:5px;">Go</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="duplicates" class="tab-content">
            <div class="section">
                <h2>Duplicate Cards</h2>
                <p style="color:#888;margin-bottom:15px;">Cards with identical content</p>
                <div class="actions" style="margin-bottom:20px;">
                    <button class="btn btn-danger" onclick="cleanDuplicates('first')" id="clean-first-btn">Delete Duplicates (Keep First)</button>
                    <button class="btn btn-danger" onclick="cleanDuplicates('largest')" id="clean-largest-btn">Delete Duplicates (Keep Largest)</button>
                    <button class="btn btn-danger" onclick="cleanDuplicatesWithDescriptionCheck('first')" id="clean-desc-btn" style="background:#e67e22;">Delete Only Matching Descriptions (Keep First)</button>
                </div>
                <div id="duplicates-list"></div>
                <div id="duplicates-loading" class="loading">Loading duplicates...</div>
            </div>
        </div>

        <div id="quarantine" class="tab-content">
            <div class="section">
                <h2>Quarantine</h2>
                <p style="color:#888;margin-bottom:15px;">Flagged cards for manual review - no files are deleted automatically</p>
                <div class="actions" style="margin-bottom:15px;">
                    <button class="btn btn-danger" onclick="deleteAllQuarantinedCards()">Delete All</button>
                </div>
                <div id="quarantine-list"></div>
                <div id="quarantine-loading" class="loading">Loading...</div>
            </div>
        </div>

        <div id="tags" class="tab-content">
            <div class="section">
                <h2>Top Tags</h2>
                <div id="tags-list"></div>
                <div id="tags-loading" class="loading">Loading tags...</div>
            </div>
        </div>

        <div id="import" class="tab-content">
            <div class="section">
                <h2>Smart Import</h2>
                <p style="color:#888;margin-bottom:15px;">Import cards from a source directory. Source files are never modified or deleted.</p>

                <div class="search-box" style="margin-bottom:20px;">
                    <input type="text" id="import-source-dir" placeholder="Source directory path (e.g., /mnt/backup/cards)">
                    <label style="display:flex;align-items:center;gap:5px;color:#888;font-size:0.9rem;">
                        <input type="checkbox" id="import-recursive" checked> Recursive
                    </label>
                    <button class="btn btn-primary" onclick="scanForImport()" id="import-scan-btn">Scan</button>
                    <button class="btn" onclick="loadLastScan()" id="import-load-last-btn" style="background:#8e44ad;">Load Last Scan</button>
                </div>

                <div id="import-status" style="margin-bottom:15px;display:none;padding:10px;background:#0f3460;border-radius:8px;">
                    <span id="import-status-text"></span>
                </div>

                <div id="import-results" style="display:none;">
                    <div class="stats-grid" style="margin-bottom:20px;">
                        <div class="stat-card success"><h3>New Cards</h3><div class="value" id="import-new-count">0</div></div>
                        <div class="stat-card"><h3>Duplicates</h3><div class="value" id="import-dupe-count">0</div></div>
                        <div class="stat-card danger"><h3>Prohibited</h3><div class="value" id="import-prohibited-count">0</div></div>
                        <div class="stat-card warning"><h3>Needs Review</h3><div class="value" id="import-quarantine-count">0</div></div>
                    </div>

                    <div class="tabs" style="margin-bottom:15px;">
                        <button class="tab active" onclick="showImportTab('new')">New Cards</button>
                        <button class="tab" onclick="showImportTab('quarantine')">Needs Review</button>
                        <button class="tab" onclick="showImportTab('prohibited')">Prohibited</button>
                        <button class="tab" onclick="showImportTab('duplicates')">Duplicates</button>
                    </div>

                    <div id="import-new-section">
                        <div class="actions" style="margin-bottom:15px;">
                            <button class="btn btn-primary" onclick="importAllNew()" id="import-all-btn">Import All New Cards</button>
                            <button class="btn btn-primary" onclick="importSelected()" id="import-selected-btn">Import Selected</button>
                            <label style="display:flex;align-items:center;gap:5px;color:#888;">
                                <input type="checkbox" id="import-select-all" onchange="toggleSelectAllImport()"> Select All
                            </label>
                        </div>
                        <div id="import-new-list" class="card-grid"></div>
                    </div>

                    <div id="import-quarantine-section" style="display:none;">
                        <div class="actions" style="margin-bottom:15px;">
                            <button class="btn btn-primary" onclick="approveAllQuarantine()">Approve All</button>
                            <button class="btn btn-danger" onclick="rejectAllQuarantine()">Reject All</button>
                        </div>
                        <div id="import-quarantine-list"></div>
                    </div>

                    <div id="import-prohibited-section" style="display:none;">
                        <p style="color:#e74c3c;margin-bottom:15px;">These cards were blocked due to prohibited content and cannot be imported.</p>
                        <div id="import-prohibited-list"></div>
                    </div>

                    <div id="import-duplicates-section" style="display:none;">
                        <p style="color:#888;margin-bottom:15px;">Duplicates are automatically skipped during import scan.</p>
                        <div id="import-duplicates-list"></div>
                    </div>
                </div>

                <div id="import-loading" class="loading" style="display:none;">Scanning source directory...</div>
            </div>
        </div>
    </div>

    <div id="toast"></div>

    <div class="modal-overlay" id="card-modal" onclick="if(event.target===this)closeModal()">
        <div class="modal">
            <button class="modal-close" onclick="closeModal()">x</button>
            <div class="modal-header">
                <img id="modal-img" src="" alt="">
                <div class="modal-header-info">
                    <h2 id="modal-name"></h2>
                    <div class="creator">by <span id="modal-creator"></span></div>
                    <div class="meta">
                        <span id="modal-nsfw" class="tag blocked" style="display:none;">NSFW</span>
                        <span id="modal-folder"></span>
                    </div>
                    <div class="modal-tags" id="modal-tags" style="margin-top:12px;"></div>
                </div>
            </div>
            <div class="modal-body">
                <div class="modal-section" id="section-description">
                    <h3>Description</h3>
                    <div class="modal-section-content" id="modal-description"></div>
                </div>
                <div class="modal-section" id="section-firstmes">
                    <h3>First Message</h3>
                    <div class="modal-section-content" id="modal-firstmes"></div>
                </div>
                <div class="modal-section" id="section-personality">
                    <h3>Personality</h3>
                    <div class="modal-section-content" id="modal-personality"></div>
                </div>
                <div class="modal-section" id="section-scenario">
                    <h3>Scenario</h3>
                    <div class="modal-section-content" id="modal-scenario"></div>
                </div>
                <div class="modal-section" id="section-mesbefore">
                    <h3>Example Messages</h3>
                    <div class="modal-section-content" id="modal-mesbefore"></div>
                </div>
                <div class="modal-section" id="section-path">
                    <h3>File Path</h3>
                    <div class="modal-section-content" id="modal-path" style="font-family:monospace;font-size:0.85rem;"></div>
                </div>
                <div style="margin-top:20px; display:flex; gap:10px; flex-wrap:wrap;">
                    <button class="btn btn-primary" id="modal-similar-btn" onclick="findSimilar()">Find Similar</button>
                    <button class="btn btn-danger" id="modal-delete-btn" onclick="deleteFromModal()">Delete Card</button>
                </div>
                <div id="similar-results" style="margin-top:20px; display:none;">
                    <h3 style="color:#888; font-size:0.9rem; margin-bottom:12px;">SIMILAR CARDS</h3>
                    <div id="similar-cards" class="dupe-cards"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        function showToast(msg, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.className = isError ? 'error' : '';
            toast.style.display = 'block';
            setTimeout(() => toast.style.display = 'none', 3000);
        }

        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stats-grid').innerHTML = `
                    <div class="stat-card success"><h3>Total Cards</h3><div class="value">${data.total_cards.toLocaleString()}</div></div>
                    <div class="stat-card"><h3>SFW Cards</h3><div class="value">${data.sfw_count.toLocaleString()}</div></div>
                    <div class="stat-card warning"><h3>NSFW Cards</h3><div class="value">${data.nsfw_count.toLocaleString()}</div></div>
                    <div class="stat-card"><h3>Unique Creators</h3><div class="value">${data.unique_creators.toLocaleString()}</div></div>
                    <div class="stat-card warning"><h3>Content Dupes</h3><div class="value">${data.content_duplicate_groups}</div></div>
                    <div class="stat-card" style="border-left-color:#e74c3c;"><h3>Image Dupes</h3><div class="value" style="color:#e74c3c;">${data.image_duplicate_groups}</div></div>
                    <div class="stat-card danger"><h3>Quarantined</h3><div class="value">${data.quarantined}</div></div>
                `;
            } catch (e) { console.error('Failed to load stats:', e); }
        }

        // Lorebook functions
        async function loadLorebookStats() {
            try {
                const res = await fetch('/api/lorebooks/stats');
                const data = await res.json();
                document.getElementById('lb-total').textContent = data.total_lorebooks.toLocaleString();
                document.getElementById('lb-nsfw').textContent = data.nsfw_count.toLocaleString();
                document.getElementById('lb-creators').textContent = data.creator_count.toLocaleString();
                document.getElementById('lb-entries').textContent = data.total_entries.toLocaleString();

                const configDirs = document.getElementById('lb-config-dirs');
                if (data.configured_dirs && data.configured_dirs.length > 0) {
                    configDirs.textContent = 'Dirs: ' + data.configured_dirs.join(', ');
                } else {
                    configDirs.innerHTML = '<span style="color:#f39c12;">LOREBOOK_DIRS not configured in .env</span>';
                }
            } catch (e) { console.error('Failed to load lorebook stats:', e); }
        }

        // Pagination state for lorebooks
        let lbCurrentPage = 1;
        let lbTotalPages = 1;
        let lbTotal = 0;
        const lbPageSize = 50;

        async function loadTopicFilter() {
            try {
                const res = await fetch('/api/lorebooks/topics');
                const data = await res.json();
                const select = document.getElementById('lb-topic-filter');
                select.innerHTML = '<option value="">All Topics</option>' +
                    data.topics.slice(0, 100).map(t =>
                        `<option value="${t.topic}">${t.topic} (${t.count})</option>`
                    ).join('');
            } catch (e) {
                console.error('Failed to load topics:', e);
            }
        }

        async function searchLorebooks(page = 1) {
            const query = document.getElementById('lb-search-input').value;
            const topicFilter = document.getElementById('lb-topic-filter').value;
            const nsfwFilter = document.getElementById('lb-nsfw-filter').value;
            const results = document.getElementById('lb-results');
            const loading = document.getElementById('lb-loading');
            const pagination = document.getElementById('lb-pagination');
            results.innerHTML = '';
            loading.style.display = 'block';
            pagination.style.display = 'none';

            const offset = (page - 1) * lbPageSize;
            let url = `/api/lorebooks?limit=${lbPageSize}&offset=${offset}`;
            if (query) url += `&q=${encodeURIComponent(query)}`;
            if (topicFilter) url += `&topics=${encodeURIComponent(topicFilter)}`;
            if (nsfwFilter) url += `&nsfw=${nsfwFilter}`;

            // Show active filters
            const activeFilters = document.getElementById('lb-active-filters');
            const filters = [];
            if (topicFilter) filters.push(`<span class="tag" style="cursor:pointer;" onclick="clearLbTopicFilter()">${topicFilter} ✕</span>`);
            if (nsfwFilter) filters.push(`<span class="tag" style="cursor:pointer;" onclick="clearLbNsfwFilter()">${nsfwFilter === 'true' ? 'NSFW' : 'SFW'} ✕</span>`);
            activeFilters.innerHTML = filters.join('');

            try {
                const res = await fetch(url);
                const data = await res.json();
                loading.style.display = 'none';

                lbTotal = data.total;
                lbCurrentPage = page;
                lbTotalPages = Math.ceil(data.total / lbPageSize);

                if (data.lorebooks.length === 0) {
                    results.innerHTML = '<div class="empty">No lorebooks found</div>';
                    return;
                }

                results.innerHTML = data.lorebooks.map(lb => `
                    <div class="card lorebook-card" onclick="openLorebook(${lb.id})" style="cursor:pointer;">
                        <div style="padding:15px;">
                            ${lb.nsfw ? '<span class="nsfw-badge" style="position:absolute;top:5px;right:5px;">NSFW</span>' : ''}
                            <h4 style="margin:0 0 5px 0;color:#fff;">${lb.name}</h4>
                            <p style="color:#888;font-size:0.85rem;margin:0 0 8px 0;">by ${lb.creator}</p>
                            <div style="display:flex;gap:10px;font-size:0.8rem;color:#667eea;margin-bottom:8px;">
                                <span>⭐ ${lb.star_count}</span>
                                <span>📖 ${lb.entry_count} entries</span>
                                <span>🔤 ${lb.token_count} tokens</span>
                            </div>
                            ${lb.topics && lb.topics.length > 0 ? `
                                <div style="display:flex;flex-wrap:wrap;gap:5px;">
                                    ${lb.topics.slice(0, 5).map(t => `<span style="background:#333;padding:2px 8px;border-radius:10px;font-size:0.75rem;">${t}</span>`).join('')}
                                </div>
                            ` : ''}
                            ${lb.keywords ? `<p style="color:#555;font-size:0.75rem;margin-top:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">Keywords: ${lb.keywords.substring(0, 100)}...</p>` : ''}
                        </div>
                    </div>
                `).join('');

                // Update pagination
                if (lbTotalPages > 1) {
                    pagination.style.display = 'block';
                    document.getElementById('lb-page-info').textContent = `Page ${lbCurrentPage} of ${lbTotalPages} (${lbTotal} lorebooks)`;
                    document.getElementById('lb-prev-page').disabled = lbCurrentPage <= 1;
                    document.getElementById('lb-next-page').disabled = lbCurrentPage >= lbTotalPages;
                    document.getElementById('lb-goto-page').max = lbTotalPages;
                    document.getElementById('lb-goto-page').value = lbCurrentPage;
                }
            } catch (e) {
                loading.style.display = 'none';
                results.innerHTML = '<div class="empty" style="color:#e74c3c;">Error loading lorebooks</div>';
                console.error('Failed to search lorebooks:', e);
            }
        }

        function lbPrevPage() {
            if (lbCurrentPage > 1) {
                searchLorebooks(lbCurrentPage - 1);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function lbNextPage() {
            if (lbCurrentPage < lbTotalPages) {
                searchLorebooks(lbCurrentPage + 1);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function lbGoToPage() {
            const page = parseInt(document.getElementById('lb-goto-page').value);
            if (page >= 1 && page <= lbTotalPages) {
                searchLorebooks(page);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function clearLbTopicFilter() {
            document.getElementById('lb-topic-filter').value = '';
            searchLorebooks(1);
        }

        function clearLbNsfwFilter() {
            document.getElementById('lb-nsfw-filter').value = '';
            searchLorebooks(1);
        }

        async function scanLorebooks() {
            const sourceDir = document.getElementById('lb-scan-dir').value.trim();
            const recursive = document.getElementById('lb-scan-recursive').checked;
            const status = document.getElementById('lb-scan-status');

            if (!sourceDir) {
                status.innerHTML = '<span style="color:#e74c3c;">Please enter a directory path</span>';
                return;
            }

            status.innerHTML = '<span style="color:#667eea;">Scanning lorebooks...</span>';

            try {
                const res = await fetch(`/api/lorebooks/scan?source_dir=${encodeURIComponent(sourceDir)}&recursive=${recursive}`, { method: 'POST' });
                const data = await res.json();

                if (!res.ok) {
                    throw new Error(data.detail || 'Scan failed');
                }

                status.innerHTML = `<span style="color:#2ecc71;">Scan complete: ${data.indexed} indexed, ${data.skipped} skipped, ${data.errors.length} errors</span>`;
                loadLorebookStats();
                searchLorebooks(1);
            } catch (e) {
                status.innerHTML = `<span style="color:#e74c3c;">Error: ${e.message}</span>`;
            }
        }

        async function rescanLorebooks() {
            const status = document.getElementById('lb-scan-status');
            status.innerHTML = '<span style="color:#667eea;">Scanning configured directories...</span>';

            try {
                const res = await fetch('/api/lorebooks/scan', { method: 'POST' });
                const data = await res.json();

                if (!res.ok) {
                    throw new Error(data.detail || 'Scan failed');
                }

                status.innerHTML = `<span style="color:#2ecc71;">Scan complete: ${data.indexed} indexed, ${data.skipped} skipped, ${data.errors.length} errors</span>`;
                loadLorebookStats();
                searchLorebooks(1);
            } catch (e) {
                status.innerHTML = `<span style="color:#e74c3c;">Error: ${e.message}</span>`;
            }
        }

        async function clearLorebooks() {
            if (!confirm('Clear all lorebooks from the index? This cannot be undone.')) return;

            const status = document.getElementById('lb-scan-status');
            try {
                const res = await fetch('/api/lorebooks/clear', { method: 'DELETE' });
                const data = await res.json();

                if (!res.ok) {
                    throw new Error(data.detail || 'Clear failed');
                }

                status.innerHTML = `<span style="color:#2ecc71;">Cleared ${data.deleted} lorebooks from index</span>`;
                loadLorebookStats();
                document.getElementById('lb-results').innerHTML = '<div class="empty">Index cleared. Click "Rescan" to re-index.</div>';
            } catch (e) {
                status.innerHTML = `<span style="color:#e74c3c;">Error: ${e.message}</span>`;
            }
        }

        async function openLorebook(id) {
            try {
                const res = await fetch(`/api/lorebooks/${id}`);
                const lb = await res.json();

                const entries = lb.content?.entries ? Object.values(lb.content.entries) : [];

                const modal = document.getElementById('card-modal');
                modal.innerHTML = `
                    <div class="modal-content" style="max-width:800px;">
                        <span class="close" onclick="closeModal()">&times;</span>
                        <h2 style="margin-top:0;">${lb.name}</h2>
                        <p style="color:#888;">by ${lb.creator}</p>

                        <div style="display:flex;gap:15px;margin:15px 0;flex-wrap:wrap;">
                            <span style="background:#333;padding:5px 10px;border-radius:5px;">⭐ ${lb.star_count} stars</span>
                            <span style="background:#333;padding:5px 10px;border-radius:5px;">📖 ${lb.entry_count} entries</span>
                            <span style="background:#333;padding:5px 10px;border-radius:5px;">🔤 ${lb.token_count} tokens</span>
                            ${lb.nsfw ? '<span style="background:#e74c3c;padding:5px 10px;border-radius:5px;">NSFW</span>' : ''}
                        </div>

                        ${lb.topics && lb.topics.length > 0 ? `
                            <div style="margin-bottom:15px;">
                                <strong>Topics:</strong>
                                ${lb.topics.map(t => `<span style="background:#444;padding:3px 8px;border-radius:10px;margin-left:5px;font-size:0.85rem;">${t}</span>`).join('')}
                            </div>
                        ` : ''}

                        ${lb.description ? `<p style="color:#aaa;">${lb.description}</p>` : ''}

                        <div style="margin:20px 0;">
                            <a href="/lorebooks/${encodeURIComponent(lb.folder)}/${encodeURIComponent(lb.file)}" target="_blank" class="btn btn-primary">
                                Download for SillyTavern
                            </a>
                        </div>

                        <h3>Entries (${entries.length})</h3>
                        <div style="max-height:400px;overflow-y:auto;">
                            ${entries.map(e => `
                                <div style="background:#1a1a2e;padding:12px;margin-bottom:10px;border-radius:8px;border-left:3px solid #667eea;">
                                    <strong style="color:#fff;">${e.name || 'Unnamed'}</strong>
                                    <p style="color:#667eea;font-size:0.8rem;margin:5px 0;">Keys: ${(e.keys || e.key || []).join(', ')}</p>
                                    <p style="color:#aaa;font-size:0.9rem;margin:0;">${(e.content || '').substring(0, 300)}${(e.content || '').length > 300 ? '...' : ''}</p>
                                </div>
                            `).join('')}
                        </div>

                        <details style="margin-top:20px;">
                            <summary style="cursor:pointer;color:#667eea;">File Path</summary>
                            <code style="display:block;background:#111;padding:10px;margin-top:10px;border-radius:5px;word-break:break-all;">${lb.file_path}</code>
                        </details>
                    </div>
                `;
                modal.style.display = 'flex';
            } catch (e) {
                console.error('Failed to load lorebook:', e);
                showToast('Failed to load lorebook', true);
            }
        }

        // Pagination state for cards
        let cardCurrentPage = 1;
        let cardTotalPages = 1;
        let cardTotal = 0;
        const cardPageSize = 50;

        async function loadTagFilter() {
            try {
                const res = await fetch('/api/tags');
                const data = await res.json();
                const select = document.getElementById('tag-filter');
                select.innerHTML = '<option value="">All Tags</option>' +
                    data.tags.slice(0, 100).map(([tag, count]) =>
                        `<option value="${tag}">${tag} (${count})</option>`
                    ).join('');
            } catch (e) {
                console.error('Failed to load tags:', e);
            }
        }

        async function searchCards(page = 1) {
            const query = document.getElementById('search-input').value;
            const tagFilter = document.getElementById('tag-filter').value;
            const nsfwFilter = document.getElementById('nsfw-filter').value;
            const results = document.getElementById('search-results');
            const loading = document.getElementById('search-loading');
            const pagination = document.getElementById('search-pagination');
            results.innerHTML = '';
            loading.style.display = 'block';
            pagination.style.display = 'none';

            const offset = (page - 1) * cardPageSize;
            let url = `/api/cards?limit=${cardPageSize}&offset=${offset}`;
            if (query) url += `&q=${encodeURIComponent(query)}`;
            if (tagFilter) url += `&tags=${encodeURIComponent(tagFilter)}`;
            if (nsfwFilter) url += `&nsfw=${nsfwFilter}`;

            // Show active filters
            const activeFilters = document.getElementById('active-filters');
            const filters = [];
            if (tagFilter) filters.push(`<span class="tag" style="cursor:pointer;" onclick="clearTagFilter()">${tagFilter} ✕</span>`);
            if (nsfwFilter) filters.push(`<span class="tag" style="cursor:pointer;" onclick="clearNsfwFilter()">${nsfwFilter === 'true' ? 'NSFW' : 'SFW'} ✕</span>`);
            activeFilters.innerHTML = filters.join('');

            try {
                const res = await fetch(url);
                const data = await res.json();
                loading.style.display = 'none';

                cardTotal = data.total;
                cardCurrentPage = page;
                cardTotalPages = Math.ceil(data.total / cardPageSize);

                if (data.results.length === 0) {
                    results.innerHTML = '<div class="empty">No cards found</div>';
                    return;
                }

                results.innerHTML = data.results.map(card => `
                    <div class="card" style="position:relative;" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}" onclick="openCardEl(this)">
                        <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" alt="${card.name}" loading="lazy"
                             onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/><text x=%2250%22 y=%2250%22 text-anchor=%22middle%22 fill=%22%23666%22>?</text></svg>'">
                        ${card.nsfw ? '<span class="nsfw-badge">NSFW</span>' : ''}
                        <div class="card-info"><h4>${card.name}</h4><p>${card.creator}</p></div>
                    </div>
                `).join('');

                // Update pagination
                if (cardTotalPages > 1) {
                    pagination.style.display = 'block';
                    document.getElementById('page-info').textContent = `Page ${cardCurrentPage} of ${cardTotalPages} (${cardTotal} cards)`;
                    document.getElementById('prev-page').disabled = cardCurrentPage <= 1;
                    document.getElementById('next-page').disabled = cardCurrentPage >= cardTotalPages;
                    document.getElementById('goto-page').max = cardTotalPages;
                    document.getElementById('goto-page').value = cardCurrentPage;
                }
            } catch (e) {
                loading.style.display = 'none';
                results.innerHTML = '<div class="empty">Error loading cards</div>';
            }
        }

        function prevPage() {
            if (cardCurrentPage > 1) {
                searchCards(cardCurrentPage - 1);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function nextPage() {
            if (cardCurrentPage < cardTotalPages) {
                searchCards(cardCurrentPage + 1);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function goToPage() {
            const page = parseInt(document.getElementById('goto-page').value);
            if (page >= 1 && page <= cardTotalPages) {
                searchCards(page);
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        function clearTagFilter() {
            document.getElementById('tag-filter').value = '';
            searchCards(1);
        }

        function clearNsfwFilter() {
            document.getElementById('nsfw-filter').value = '';
            searchCards(1);
        }

        async function loadDuplicates() {
            const list = document.getElementById('duplicates-list');
            const loading = document.getElementById('duplicates-loading');
            try {
                const res = await fetch('/api/duplicates');
                const data = await res.json();
                loading.style.display = 'none';
                if (data.duplicates.length === 0) {
                    list.innerHTML = '<div class="empty">No duplicates found</div>';
                    return;
                }
                list.innerHTML = `<p style="margin-bottom:15px;"><span style="color:#667eea;">${data.content_duplicate_groups} content duplicates</span> | <span style="color:#e74c3c;">${data.image_duplicate_groups} image duplicates</span></p>` + data.duplicates.map((dupe, idx) => `
                    <div class="dupe-group" id="dupe-group-${idx}" data-paths="${encodeURIComponent(JSON.stringify(dupe.cards.map(c => c.path)))}">
                        <button class="ignore-btn" onclick="ignoreDuplicateGroup(${idx})">Not a Duplicate</button>
                        <h4>${dupe.count} copies <span class="type-badge ${dupe.type}">${dupe.type === 'content' ? 'Content Match' : 'Image Match'}</span></h4>
                        <div class="dupe-cards">
                            ${dupe.cards.map((card, i) => `
                                <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                                    ${i === 0 ? '<span class="keep-badge">KEEP</span>' : ''}
                                    <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete">x</button>
                                    <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" onclick="openCardEl(this.parentElement)" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'" loading="lazy">
                                    <div class="info"><h5>${card.name}</h5><p>${card.creator}</p></div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading duplicates</div>';
            }
        }

        function openCardEl(el) {
            const folder = decodeURIComponent(el.dataset.folder);
            const file = decodeURIComponent(el.dataset.file);
            openCard(folder, file);
        }

        function deleteCardEl(el) {
            const path = decodeURIComponent(el.dataset.path);
            deleteCardByPath(path, el);
        }

        async function deleteCardByPath(path, card) {
            if (!confirm('Delete this card permanently?')) return;
            const btn = card.querySelector('.delete-btn');
            if (btn) { btn.disabled = true; btn.textContent = '...'; }
            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    card.classList.add('deleted');
                    showToast('Card deleted');
                    loadStats();
                } else {
                    showToast('Delete failed', true);
                    if (btn) { btn.disabled = false; btn.textContent = 'x'; }
                }
            } catch (e) {
                showToast('Delete error', true);
                if (btn) { btn.disabled = false; btn.textContent = 'x'; }
            }
        }

        async function ignoreDuplicateGroup(idx) {
            const group = document.getElementById('dupe-group-' + idx);
            const paths = JSON.parse(decodeURIComponent(group.dataset.paths));
            const btn = group.querySelector('.ignore-btn');
            btn.disabled = true;
            btn.textContent = 'Saving...';
            try {
                const params = paths.map(p => 'paths=' + encodeURIComponent(p)).join('&');
                const res = await fetch('/api/duplicates/ignore?' + params, { method: 'POST' });
                if (res.ok) {
                    group.style.opacity = '0.3';
                    showToast('Marked as not a duplicate');
                    setTimeout(() => group.remove(), 1000);
                    loadStats();
                } else {
                    showToast('Failed', true);
                    btn.disabled = false;
                    btn.textContent = 'Not a Duplicate';
                }
            } catch (e) {
                showToast('Error', true);
                btn.disabled = false;
                btn.textContent = 'Not a Duplicate';
            }
        }

        async function cleanDuplicates(keep) {
            if (!confirm(`Delete all duplicate files, keeping the ${keep} copy?`)) return;
            document.getElementById('clean-first-btn').disabled = true;
            document.getElementById('clean-largest-btn').disabled = true;
            try {
                const res = await fetch(`/api/duplicates/clean?keep=${keep}`, { method: 'DELETE' });
                const data = await res.json();
                showToast(`Deleted ${data.deleted_count} duplicate files`);
                loadDuplicates();
                loadStats();
            } catch (e) { showToast('Error cleaning duplicates', true); }
            document.getElementById('clean-first-btn').disabled = false;
            document.getElementById('clean-largest-btn').disabled = false;
        }

        async function cleanDuplicatesWithDescriptionCheck(keep) {
            if (!confirm(`Delete duplicate files with IDENTICAL descriptions only, keeping the ${keep} copy?`)) return;
            document.getElementById('clean-desc-btn').disabled = true;
            try {
                const res = await fetch(`/api/duplicates/clean?keep=${keep}&check_description=true`, { method: 'DELETE' });
                const data = await res.json();
                showToast(`Deleted ${data.deleted_count} duplicate files with matching descriptions`);
                loadDuplicates();
                loadStats();
            } catch (e) { 
                showToast('Error cleaning duplicates', true); 
            }
            document.getElementById('clean-desc-btn').disabled = false;
        }

        async function loadQuarantine() {
            const list = document.getElementById('quarantine-list');
            const loading = document.getElementById('quarantine-loading');
            try {
                const res = await fetch('/api/quarantine');
                const data = await res.json();
                loading.style.display = 'none';
                if (data.cards.length === 0) {
                    list.innerHTML = '<div class="empty">No cards in quarantine</div>';
                    return;
                }
                
                let html = '<div class="card-grid">';
                data.cards.forEach(card => {
                    const statusColor = card.status === 'block' ? '#e74c3c' : '#f39c12';
                    const statusLabel = card.status === 'block' ? 'HIGH PRIORITY' : 'REVIEW';
                    const matchesHtml = card.matches.map(m => '<p style="font-family:monospace;font-size:0.8rem;color:#e74c3c;">' + m + '</p>').join('');
                    
                    html += `
                        <div class="card" style="position:relative;" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                            <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" 
                                 alt="${card.name || 'Unknown'}" 
                                 loading="lazy"
                                 onclick="openCardEl(this.parentElement)"
                                 onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'">
                            <div class="card-info">
                                <h4>${card.name || 'Unknown'}</h4>
                                <p>${card.creator || 'Unknown'}</p>
                            </div>
                            <div class="actions" style="margin-top:10px;">
                                <button class="btn btn-sm" onclick="approveQuarantinedCard('${card.path.replace(/'/g, "\\'")}')">Approve</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteQuarantinedCard('${card.path.replace(/'/g, "\\'")}')">Delete</button>
                            </div>
                            <div style="background:#1a1a2e;padding:10px;border-radius:6px;margin-top:10px;">
                                <p style="font-size:0.85rem;color:#888;">Matched content:</p>
                                ${matchesHtml}
                            </div>
                        </div>
                    `;
                });
                html += '</div>';
                list.innerHTML = html;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="error">Failed to load quarantine</div>';
            }
        }

        async function deleteQuarantinedCard(path) {
            if (!confirm(`Delete this card permanently?\n\n${path}`)) return;
            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
                if (res.ok) {
                    showToast('Card deleted');
                    loadQuarantine();
                    loadStats();
                } else {
                    showToast('Failed to delete card', true);
                }
            } catch (e) {
                showToast('Error deleting card', true);
            }
        }

        async function approveQuarantinedCard(path) {
            if (!confirm(`Approve this card?\\n\\n${path}\\n\\nThis will remove it from quarantine but keep it in the index.`)) return;
            try {
                const res = await fetch(`/api/quarantine/approve?path=${encodeURIComponent(path)}`, { method: 'POST' });
                if (res.ok) {
                    showToast('Card approved');
                    loadQuarantine();
                    loadStats();
                } else {
                    showToast('Failed to approve card', true);
                }
            } catch (e) {
                showToast('Error approving card', true);
            }
        }

        async function deleteAllQuarantinedCards() {
            if (!confirm('Delete ALL cards in quarantine permanently?\\n\\nThis action cannot be undone!')) return;
            try {
                const res = await fetch('/api/quarantine/delete-all', { method: 'DELETE' });
                if (res.ok) {
                    const data = await res.json();
                    showToast(`Deleted ${data.deleted_count} cards`);
                    loadQuarantine();
                    loadStats();
                } else {
                    showToast('Failed to delete quarantined cards', true);
                }
            } catch (e) {
                showToast('Error deleting quarantined cards', true);
            }
        }

        async function viewCard(path) {
            // Extract folder and filename from path
            const parts = path.split(/[\\/]/);
            const filename = parts.pop();
            const folder = parts.pop();
            window.open(`/cards/${folder}/${filename}`, '_blank');
        }

        async function loadTags() {
            const list = document.getElementById('tags-list');
            const loading = document.getElementById('tags-loading');
            try {
                const res = await fetch('/api/tags');
                const data = await res.json();
                loading.style.display = 'none';
                list.innerHTML = `<table><thead><tr><th>Tag</th><th>Count</th></tr></thead><tbody>${data.tags.slice(0, 100).map(([tag, count]) => `<tr><td><span class="tag">${tag}</span></td><td>${count.toLocaleString()}</td></tr>`).join('')}</tbody></table>`;
            } catch (e) {
                loading.style.display = 'none';
                list.innerHTML = '<div class="empty">Error loading tags</div>';
            }
        }

        document.getElementById('search-input').addEventListener('keypress', e => { if (e.key === 'Enter') searchCards(1); });
        document.getElementById('goto-page').addEventListener('keypress', e => { if (e.key === 'Enter') goToPage(); });

        let currentCardPath = '';

        function closeModal() {
            document.getElementById('card-modal').classList.remove('active');
            currentCardPath = '';
        }

        async function findSimilar() {
            if (!currentCardPath) return;
            const btn = document.getElementById('modal-similar-btn');
            const resultsDiv = document.getElementById('similar-results');
            const cardsDiv = document.getElementById('similar-cards');
            btn.disabled = true;
            btn.textContent = 'Searching...';
            resultsDiv.style.display = 'none';
            try {
                const res = await fetch(`/api/cards/similar?path=${encodeURIComponent(currentCardPath)}&threshold=20`);
                const data = await res.json();
                if (data.similar.length === 0) {
                    cardsDiv.innerHTML = '<p style="color:#888;">No similar cards found</p>';
                } else {
                    cardsDiv.innerHTML = data.similar.map(card => `
                        <div class="dupe-card" data-path="${encodeURIComponent(card.path)}" data-folder="${encodeURIComponent(card.folder)}" data-file="${encodeURIComponent(card.file)}">
                            <button class="delete-btn" onclick="event.stopPropagation(); deleteCardEl(this.parentElement)" title="Delete">x</button>
                            <img src="/cards/${encodeURIComponent(card.folder)}/${encodeURIComponent(card.file)}" onclick="openCardEl(this.parentElement)" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%23333%22 width=%22100%22 height=%22100%22/></svg>'" loading="lazy">
                            <div class="info"><h5>${card.name}</h5><p>${card.creator}</p><p style="color:#667eea;font-size:0.7rem;">${card.reasons.join(', ')}</p></div>
                        </div>
                    `).join('');
                }
                resultsDiv.style.display = 'block';
                showToast(`Found ${data.similar.length} similar cards`);
            } catch (e) { showToast('Search error', true); }
            btn.disabled = false;
            btn.textContent = 'Find Similar';
        }

        async function deleteFromModal() {
            if (!currentCardPath) return;
            if (!confirm('Delete this card permanently?')) return;
            const btn = document.getElementById('modal-delete-btn');
            btn.disabled = true;
            btn.textContent = 'Deleting...';
            try {
                const res = await fetch(`/api/cards/delete?path=${encodeURIComponent(currentCardPath)}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    showToast('Card deleted');
                    closeModal();
                    loadStats();
                    searchCards(1);
                    loadDuplicates();
                } else { showToast('Delete failed', true); }
            } catch (e) { showToast('Delete error', true); }
            btn.disabled = false;
            btn.textContent = 'Delete Card';
        }

        async function openCard(folder, file) {
            const modal = document.getElementById('card-modal');
            modal.classList.add('active');
            document.getElementById('modal-img').src = `/cards/${encodeURIComponent(folder)}/${encodeURIComponent(file)}`;
            document.getElementById('modal-name').textContent = 'Loading...';
            document.getElementById('modal-creator').textContent = '';
            document.getElementById('modal-tags').innerHTML = '';
            document.getElementById('similar-results').style.display = 'none';
            try {
                const res = await fetch(`/api/cards/${encodeURIComponent(folder)}/${encodeURIComponent(file)}`);
                const data = await res.json();
                const entry = data.entry;
                const meta = data.full_metadata?.data || data.full_metadata || {};
                document.getElementById('modal-name').textContent = entry.name || meta.name || file;
                document.getElementById('modal-creator').textContent = entry.creator || meta.creator || 'Unknown';
                document.getElementById('modal-folder').textContent = entry.folder + '/' + entry.file;
                document.getElementById('modal-path').textContent = entry.path;
                currentCardPath = entry.path;
                document.getElementById('modal-nsfw').style.display = entry.nsfw ? 'inline-block' : 'none';
                const tags = entry.tags || meta.tags || [];
                document.getElementById('modal-tags').innerHTML = tags.slice(0, 20).map(t => `<span class="tag">${t}</span>`).join('') + (tags.length > 20 ? `<span class="tag">+${tags.length - 20} more</span>` : '');
                setSection('description', meta.description || entry.description_preview || '');
                setSection('firstmes', meta.first_mes || entry.first_mes_preview || '');
                setSection('personality', meta.personality || '');
                setSection('scenario', meta.scenario || '');
                setSection('mesbefore', meta.mes_example || '');
            } catch (e) {
                document.getElementById('modal-name').textContent = 'Error loading card';
            }
        }

        function setSection(id, content) {
            const section = document.getElementById('section-' + id);
            const el = document.getElementById('modal-' + id);
            if (content && content.trim()) { section.style.display = 'block'; el.textContent = content; }
            else { section.style.display = 'none'; }
        }

        document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

        async function triggerNextcloudScan() {
            const btn = document.getElementById('nextcloud-btn');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            try {
                const res = await fetch('/api/nextcloud/scan', { method: 'POST' });
                const data = await res.json();
                if (data.success) { showToast('Nextcloud scan completed!'); }
                else { showToast('Nextcloud scan failed', true); }
            } catch (e) { showToast('Nextcloud scan error', true); }
            btn.disabled = false;
            btn.textContent = 'Refresh Nextcloud';
        }

        async function triggerRescan() {
            const btn = document.getElementById('rescan-btn');
            btn.disabled = true;
            btn.textContent = 'Starting...';
            try {
                const res = await fetch('/api/index/rescan', { method: 'POST' });
                if (res.ok) { showToast('Rescan started'); checkScanStatus(); }
                else {
                    const data = await res.json();
                    showToast(data.detail || 'Failed', true);
                    btn.disabled = false;
                    btn.textContent = 'Rescan Index';
                }
            } catch (e) {
                showToast('Error', true);
                btn.disabled = false;
                btn.textContent = 'Rescan Index';
            }
        }

        async function checkScanStatus() {
            try {
                const res = await fetch('/api/index/status');
                const data = await res.json();
                const status = document.getElementById('scan-status');
                const btn = document.getElementById('rescan-btn');
                if (data.scan_running) {
                    status.textContent = `Scanning... ${data.scan_progress} processed`;
                    status.style.color = '#f39c12';
                    btn.disabled = true;
                    btn.textContent = 'Scanning...';
                    setTimeout(checkScanStatus, 2000);
                } else {
                    if (data.last_scan) { status.textContent = `${data.cards_indexed} cards indexed`; status.style.color = '#2ecc71'; }
                    btn.disabled = false;
                    btn.textContent = 'Rescan Index';
                    loadStats();
                }
            } catch (e) { console.error('Failed to check scan status:', e); }
        }

        loadStats();
        loadLorebookStats();
        loadDuplicates();
        loadQuarantine();
        loadTags();
        loadTagFilter();
        loadTopicFilter();
        searchCards(1);
        checkScanStatus();

        // ===== IMPORT FUNCTIONS =====
        let importScanResults = null;
        let selectedForImport = new Set();

        let importStatusInterval = null;

        async function pollImportStatus() {
            try {
                const res = await fetch('/api/import/status');
                const status = await res.json();
                const statusText = document.getElementById('import-status-text');

                if (status.running) {
                    let text = '';
                    if (status.phase === 'discovering') {
                        text = 'Discovering files... Found ' + status.progress + ' files';
                        if (status.skipped_existing > 0) text += ', ' + status.skipped_existing + ' already indexed';
                    } else if (status.phase === 'analyzing') {
                        const pct = status.total > 0 ? Math.round((status.progress / status.total) * 100) : 0;
                        text = 'Analyzing: ' + status.progress + '/' + status.total + ' (' + pct + '%)';
                        if (status.current_file) text += '<br>' + status.current_file;
                        text += '<br>✓ ' + status.new_cards + ' new | ⊘ ' + status.skipped_duplicates + ' dupes | ⛔ ' + status.prohibited + ' prohibited | ⚠ ' + status.quarantine + ' quarantine';
                    } else if (status.phase === 'complete') {
                        text = 'Processing results...';
                    } else {
                        text = status.message || 'Working...';
                    }
                    statusText.innerHTML = text;
                }
                return status;
            } catch (e) {
                console.error('Failed to poll import status:', e);
                return null;
            }
        }

        async function scanForImport() {
            const sourceDir = document.getElementById('import-source-dir').value.trim();
            if (!sourceDir) {
                showToast('Please enter a source directory', true);
                return;
            }

            const recursive = document.getElementById('import-recursive').checked;
            const btn = document.getElementById('import-scan-btn');
            const loading = document.getElementById('import-loading');
            const results = document.getElementById('import-results');
            const status = document.getElementById('import-status');

            btn.disabled = true;
            btn.textContent = 'Scanning...';
            loading.style.display = 'block';
            results.style.display = 'none';
            status.style.display = 'block';
            status.querySelector('#import-status-text').textContent = 'Starting scan...';

            // Start polling for progress
            importStatusInterval = setInterval(pollImportStatus, 500);

            try {
                const res = await fetch(`/api/import/scan?source_dir=${encodeURIComponent(sourceDir)}&recursive=${recursive}`, { method: 'POST' });
                const data = await res.json();

                if (!res.ok) {
                    throw new Error(data.detail || 'Scan failed');
                }

                importScanResults = data;
                selectedForImport.clear();

                // Update counts
                document.getElementById('import-new-count').textContent = data.summary.new_cards;
                document.getElementById('import-dupe-count').textContent = data.skipped_duplicates || 0;
                document.getElementById('import-prohibited-count').textContent = data.summary.prohibited;
                document.getElementById('import-quarantine-count').textContent = data.summary.quarantine;

                const skippedExisting = data.skipped_existing || 0;
                const skippedDupes = data.skipped_duplicates || 0;

                // Render lists
                renderImportNewList(data.new_cards);
                renderImportQuarantineList(data.quarantine);
                renderImportProhibitedList(data.prohibited);
                renderImportDuplicatesList(skippedDupes);
                const totalSkipped = skippedExisting + skippedDupes;
                const processed = data.files_processed || data.total_files;
                const statusMsg = totalSkipped > 0
                    ? `Scan complete: ${data.total_files} files (${skippedExisting} indexed, ${skippedDupes} duplicates skipped, ${data.summary.new_cards} new)`
                    : `Scan complete: ${data.total_files} files, ${data.summary.new_cards} new`;
                status.querySelector('#import-status-text').textContent = statusMsg;
                status.querySelector('#import-status-text').style.color = '#2ecc71';
                results.style.display = 'block';
                showImportTab('new');

            } catch (e) {
                status.querySelector('#import-status-text').textContent = 'Error: ' + e.message;
                status.querySelector('#import-status-text').style.color = '#e74c3c';
                showToast('Scan failed: ' + e.message, true);
            } finally {
                // Stop polling for progress
                if (importStatusInterval) {
                    clearInterval(importStatusInterval);
                    importStatusInterval = null;
                }
            }

            loading.style.display = 'none';
            btn.disabled = false;
            btn.textContent = 'Scan';
        }

        function showImportTab(tab) {
            const sections = ['new', 'quarantine', 'prohibited', 'duplicates'];
            const tabs = document.querySelectorAll('#import-results .tabs .tab');

            sections.forEach((s, i) => {
                document.getElementById(`import-${s}-section`).style.display = s === tab ? 'block' : 'none';
                tabs[i].classList.toggle('active', s === tab);
            });
        }

        let importNewPage = 0;
        const IMPORT_PAGE_SIZE = 100;

        function renderImportNewList(cards) {
            const container = document.getElementById('import-new-section');
            const list = document.getElementById('import-new-list');

            if (!cards || cards.length === 0) {
                list.innerHTML = '<div class="empty">No new cards found</div>';
                return;
            }

            // Add controls if not present
            let controls = container.querySelector('.import-controls');
            if (!controls) {
                controls = document.createElement('div');
                controls.className = 'import-controls';
                controls.style.cssText = 'display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center;';
                container.insertBefore(controls, list);
            }

            const totalPages = Math.ceil(cards.length / IMPORT_PAGE_SIZE);
            const start = importNewPage * IMPORT_PAGE_SIZE;
            const end = Math.min(start + IMPORT_PAGE_SIZE, cards.length);
            const pageCards = cards.slice(start, end);

            const selectedCount = selectedForImport.size;
            controls.innerHTML = `
                <button class="btn btn-primary" onclick="selectAllOnPage()">Select Page (${pageCards.length})</button>
                <button class="btn btn-primary" onclick="selectAllCards()">Select All (${cards.length})</button>
                <button class="btn" onclick="clearSelection()">Clear Selection</button>
                <button id="import-selected-btn" class="btn btn-success" onclick="importSelected()" style="background:#3498db;" ${selectedCount === 0 ? 'disabled' : ''}>
                    ${selectedCount > 0 ? 'Import Selected (' + selectedCount + ')' : 'Import Selected'}
                </button>
                <button class="btn btn-success" onclick="importAllNew()" style="background:#27ae60;">Import All ${cards.length}</button>
                <br style="width:100%;">
                <span style="color:#888;">
                    Showing ${start + 1}-${end} of ${cards.length}
                    ${totalPages > 1 ? ' | Page ' + (importNewPage + 1) + '/' + totalPages : ''}
                </span>
                ${totalPages > 1 ? `
                    <button class="btn" onclick="importNewPrevPage()" ${importNewPage === 0 ? 'disabled' : ''}>← Prev</button>
                    <button class="btn" onclick="importNewNextPage()" ${importNewPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
                ` : ''}
            `;

            list.innerHTML = pageCards.map(card => `
                <div class="card" style="position:relative;" data-path="${encodeURIComponent(card.path)}">
                    <input type="checkbox" class="import-checkbox" style="position:absolute;top:8px;left:8px;z-index:10;width:20px;height:20px;"
                           ${selectedForImport.has(card.path) ? 'checked' : ''}
                           onchange="toggleImportSelect('${encodeURIComponent(card.path)}')">
                    ${card.nsfw ? '<span class="nsfw-badge">NSFW</span>' : ''}
                    <div style="width:100%;aspect-ratio:1;background:#0f3460;display:flex;align-items:center;justify-content:center;color:#666;">
                        <span style="font-size:2rem;">?</span>
                    </div>
                    <div class="card-info">
                        <h4>${card.name || card.file}</h4>
                        <p>${card.creator || 'Unknown'}</p>
                        <p style="font-size:0.7rem;color:#667eea;">${card.folder}</p>
                    </div>
                </div>
            `).join('');
        }

        function importNewPrevPage() {
            if (importNewPage > 0) {
                importNewPage--;
                renderImportNewList(importScanResults.new_cards);
            }
        }

        function importNewNextPage() {
            const totalPages = Math.ceil(importScanResults.new_cards.length / IMPORT_PAGE_SIZE);
            if (importNewPage < totalPages - 1) {
                importNewPage++;
                renderImportNewList(importScanResults.new_cards);
            }
        }

        function selectAllOnPage() {
            const start = importNewPage * IMPORT_PAGE_SIZE;
            const end = Math.min(start + IMPORT_PAGE_SIZE, importScanResults.new_cards.length);
            for (let i = start; i < end; i++) {
                selectedForImport.add(importScanResults.new_cards[i].path);
            }
            renderImportNewList(importScanResults.new_cards);
            updateImportButton();
        }

        function selectAllCards() {
            importScanResults.new_cards.forEach(card => selectedForImport.add(card.path));
            renderImportNewList(importScanResults.new_cards);
            updateImportButton();
        }

        function clearSelection() {
            selectedForImport.clear();
            renderImportNewList(importScanResults.new_cards);
            updateImportButton();
        }

        async function importAllNew() {
            if (!importScanResults || !importScanResults.new_cards.length) return;

            const paths = importScanResults.new_cards.map(c => c.path);
            if (!confirm('Import all ' + paths.length + ' cards? This may take a while.')) return;

            await executeImportBatch(paths);
        }

        async function loadLastScan() {
            const btn = document.getElementById('import-load-last-btn');
            const status = document.getElementById('import-status');
            const results = document.getElementById('import-results');

            btn.disabled = true;
            btn.textContent = 'Loading...';
            status.style.display = 'block';
            status.querySelector('#import-status-text').textContent = 'Loading last scan results...';

            try {
                const res = await fetch('/api/import/last-scan');
                if (!res.ok) {
                    throw new Error('No previous scan found');
                }
                const data = await res.json();

                importScanResults = {
                    new_cards: data.new_cards || [],
                    prohibited: data.prohibited || [],
                    quarantine: data.quarantine || [],
                    skipped_existing: data.skipped_existing || 0,
                    skipped_duplicates: data.skipped_duplicates || 0,
                    total_files: data.total_files || 0
                };
                selectedForImport.clear();
                importNewPage = 0;

                // Update counts
                document.getElementById('import-new-count').textContent = importScanResults.new_cards.length;
                document.getElementById('import-dupe-count').textContent = importScanResults.skipped_duplicates;
                document.getElementById('import-prohibited-count').textContent = importScanResults.prohibited.length;
                document.getElementById('import-quarantine-count').textContent = importScanResults.quarantine.length;

                // Render lists
                renderImportNewList(importScanResults.new_cards);
                renderImportQuarantineList(importScanResults.quarantine);
                renderImportProhibitedList(importScanResults.prohibited);
                renderImportDuplicatesList(importScanResults.skipped_duplicates);

                status.querySelector('#import-status-text').textContent =
                    'Loaded scan from ' + (data.scanned_at || 'unknown time') + ': ' + importScanResults.new_cards.length + ' new cards';
                status.querySelector('#import-status-text').style.color = '#2ecc71';
                results.style.display = 'block';
                showImportTab('new');

            } catch (e) {
                status.querySelector('#import-status-text').textContent = 'Error: ' + e.message;
                status.querySelector('#import-status-text').style.color = '#e74c3c';
                showToast('Failed to load last scan: ' + e.message, true);
            }

            btn.disabled = false;
            btn.textContent = 'Load Last Scan';
        }

        function renderImportQuarantineList(cards) {
            const list = document.getElementById('import-quarantine-list');
            if (!cards || cards.length === 0) {
                list.innerHTML = '<div class="empty">No cards in quarantine</div>';
                return;
            }
            list.innerHTML = cards.map(card => `
                <div class="dupe-group" data-path="${encodeURIComponent(card.path)}">
                    <h4>${card.name || card.file}</h4>
                    <p style="color:#888;margin-bottom:10px;">by ${card.creator || 'Unknown'}</p>
                    <p style="color:#f39c12;margin-bottom:10px;"><strong>Reason:</strong> ${card.reason}</p>
                    <div style="background:#1a1a2e;padding:10px;border-radius:6px;margin-bottom:10px;">
                        <p style="font-size:0.85rem;color:#888;">Matched content:</p>
                        ${card.matches.map(m => `<p style="font-family:monospace;font-size:0.8rem;color:#e74c3c;">${m}</p>`).join('')}
                    </div>
                    <div class="actions">
                        <button class="btn btn-primary" onclick="reviewQuarantine('${encodeURIComponent(card.path)}', 'approve')">Approve & Import</button>
                        <button class="btn btn-danger" onclick="reviewQuarantine('${encodeURIComponent(card.path)}', 'reject')">Reject</button>
                    </div>
                </div>
            `).join('');
        }

        function renderImportProhibitedList(cards) {
            const list = document.getElementById('import-prohibited-list');
            if (!cards || cards.length === 0) {
                list.innerHTML = '<div class="empty">No prohibited cards found</div>';
                return;
            }
            list.innerHTML = cards.map(card => `
                <div class="dupe-group" style="border-left:4px solid #e74c3c;">
                    <h4>${card.name || card.file}</h4>
                    <p style="color:#888;">by ${card.creator || 'Unknown'}</p>
                    <p style="color:#e74c3c;"><strong>Blocked:</strong> ${card.reason}</p>
                    <div style="margin-top:8px;">
                        ${(card.matches || []).map(m => `<span class="tag blocked">${m}</span>`).join('')}
                    </div>
                    <p style="font-family:monospace;font-size:0.75rem;color:#666;margin-top:8px;">${card.path}</p>
                </div>
            `).join('');
        }

        function renderImportDuplicatesList(count) {
            const list = document.getElementById('import-duplicates-list');
            if (!count || count === 0) {
                list.innerHTML = '<div class="empty">No duplicates detected</div>';
                return;
            }
            list.innerHTML = `<div class="empty" style="color:#2ecc71;">${count} duplicate files automatically skipped</div>`;
        }

        function toggleImportSelect(encodedPath) {
            const path = decodeURIComponent(encodedPath);
            if (selectedForImport.has(path)) {
                selectedForImport.delete(path);
            } else {
                selectedForImport.add(path);
            }
            updateImportButton();
        }

        function updateImportButton() {
            const count = selectedForImport.size;
            const btn = document.getElementById('import-selected-btn');
            if (btn) {
                btn.textContent = count > 0 ? `Import Selected (${count})` : 'Import Selected';
                btn.disabled = count === 0;
            }
        }

        async function importSelected() {
            if (selectedForImport.size === 0) {
                showToast('No cards selected', true);
                return;
            }
            const paths = Array.from(selectedForImport);
            await executeImportBatch(paths);
        }

        function toggleSelectAllImport() {
            const selectAll = document.getElementById('import-select-all').checked;
            const checkboxes = document.querySelectorAll('.import-checkbox');

            checkboxes.forEach(cb => {
                cb.checked = selectAll;
                const card = cb.closest('.card');
                const path = decodeURIComponent(card.dataset.path);
                if (selectAll) {
                    selectedForImport.add(path);
                } else {
                    selectedForImport.delete(path);
                }
            });
        }

        async function importAllNew() {
            if (!importScanResults || !importScanResults.new_cards.length) {
                showToast('No new cards to import', true);
                return;
            }

            if (!confirm(`Import all ${importScanResults.new_cards.length} new cards?`)) return;

            const paths = importScanResults.new_cards.map(c => c.path);
            await executeImport(paths);
        }

        async function importSelected() {
            if (selectedForImport.size === 0) {
                showToast('No cards selected', true);
                return;
            }

            if (!confirm(`Import ${selectedForImport.size} selected cards?`)) return;

            await executeImport(Array.from(selectedForImport));
        }

        async function executeImport(paths) {
            return executeImportBatch(paths);
        }

        async function executeImportBatch(paths) {
            const statusText = document.getElementById('import-status-text');
            const BATCH_SIZE = 50;
            let totalImported = 0;
            let totalFailed = 0;

            statusText.style.color = '#3498db';

            for (let i = 0; i < paths.length; i += BATCH_SIZE) {
                const batch = paths.slice(i, i + BATCH_SIZE);
                const batchNum = Math.floor(i / BATCH_SIZE) + 1;
                const totalBatches = Math.ceil(paths.length / BATCH_SIZE);

                statusText.textContent = `Importing batch ${batchNum}/${totalBatches} (${i + batch.length}/${paths.length} cards)...`;

                try {
                    const params = batch.map(p => `source_paths=${encodeURIComponent(p)}`).join('&');
                    const res = await fetch(`/api/import/execute?${params}`, { method: 'POST' });
                    const data = await res.json();

                    if (data.success) {
                        totalImported += data.imported_count;
                        totalFailed += data.failed_count;

                        // Log DB count for debugging
                        console.log(`Batch ${batchNum}: imported=${data.imported_count}, DB total=${data.total_cards_in_db}`);

                        // Remove imported cards from the data
                        const importedPaths = new Set(batch);
                        importScanResults.new_cards = importScanResults.new_cards.filter(c => !importedPaths.has(c.path));

                        // Clear selection for imported cards
                        batch.forEach(p => selectedForImport.delete(p));

                        // Store final DB count
                        window.lastImportDbCount = data.total_cards_in_db;
                    }
                } catch (e) {
                    console.error('Batch import error:', e);
                    totalFailed += batch.length;
                }
            }

            // Update UI with DB count verification
            const dbCountMsg = window.lastImportDbCount ? ` (DB total: ${window.lastImportDbCount})` : '';
            statusText.textContent = `Import complete: ${totalImported} imported, ${totalFailed} failed, ${importScanResults.new_cards.length} remaining${dbCountMsg}`;
            statusText.style.color = '#2ecc71';

            document.getElementById('import-new-count').textContent = importScanResults.new_cards.length;
            importNewPage = 0;
            renderImportNewList(importScanResults.new_cards);
            loadStats();

            showToast(`Imported ${totalImported} cards (${totalFailed} failed)`);
        }

        async function reviewQuarantine(encodedPath, decision) {
            const path = decodeURIComponent(encodedPath);

            try {
                const res = await fetch(`/api/import/quarantine/review?source_path=${encodeURIComponent(path)}&decision=${decision}`, { method: 'POST' });
                const data = await res.json();

                if (decision === 'approve') {
                    showToast('Card approved and imported');
                    loadStats();
                } else {
                    showToast('Card rejected');
                }

                // Remove from list
                const group = document.querySelector(`.dupe-group[data-path="${encodedPath}"]`);
                if (group) group.remove();

                // Update count
                const count = parseInt(document.getElementById('import-quarantine-count').textContent);
                document.getElementById('import-quarantine-count').textContent = Math.max(0, count - 1);

            } catch (e) {
                showToast('Review error: ' + e.message, true);
            }
        }

        async function approveAllQuarantine() {
            if (!confirm('Approve and import ALL quarantined cards?')) return;

            try {
                const res = await fetch('/api/import/quarantine/bulk-review?decision=approve', { method: 'POST' });
                const data = await res.json();
                showToast(`Approved ${data.reviewed} cards, imported ${data.imported}`);
                document.getElementById('import-quarantine-list').innerHTML = '<div class="empty">All cards reviewed</div>';
                document.getElementById('import-quarantine-count').textContent = '0';
                loadStats();
            } catch (e) {
                showToast('Bulk approve error: ' + e.message, true);
            }
        }

        async function rejectAllQuarantine() {
            if (!confirm('Reject ALL quarantined cards?')) return;

            try {
                const res = await fetch('/api/import/quarantine/bulk-review?decision=reject', { method: 'POST' });
                const data = await res.json();
                showToast(`Rejected ${data.reviewed} cards`);
                document.getElementById('import-quarantine-list').innerHTML = '<div class="empty">All cards reviewed</div>';
                document.getElementById('import-quarantine-count').textContent = '0';
            } catch (e) {
                showToast('Bulk reject error: ' + e.message, true);
            }
        }
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the web dashboard."""
    return DASHBOARD_HTML


@app.get("/api/info")
async def api_info():
    duplicates = index.get_duplicates()
    return {
        "service": "Character Card Index",
        "version": "2.0.0-sqlite",
        "total_cards": index.get_card_count(),
        "quarantined": index.get_quarantine_count(),
        "duplicate_groups": len(duplicates),
        "config": {
            "detect_duplicates": DETECT_DUPLICATES,
            "database": DB_FILE
        },
        "endpoints": {
            "search": "/api/cards",
            "card_detail": "/api/cards/{folder}/{filename}",
            "card_image": "/cards/{folder}/{filename}",
            "stats": "/api/stats",
            "tags": "/api/tags",
            "quarantine": "/api/quarantine",
            "duplicates": "/api/duplicates",
            "clean_duplicates": "DELETE /api/duplicates/clean"
        }
    }


@app.get("/api/cards")
async def search_cards(
    q: Optional[str] = Query(None, description="Search query"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    nsfw: Optional[bool] = Query(None, description="Filter by NSFW"),
    creator: Optional[str] = Query(None, description="Filter by creator"),
    folder: Optional[str] = Query(None, description="Filter by folder"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Search character cards with filters."""
    tag_list = [t.strip() for t in tags.split(",")] if tags else None

    results, total = index.search(
        query=q,
        tags=tag_list,
        nsfw=nsfw,
        creator=creator,
        folder=folder,
        limit=limit,
        offset=offset
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": [asdict(c) for c in results]
    }


@app.get("/api/cards/{folder}/{filename}")
async def get_card(folder: str, filename: str):
    """Get full metadata for a specific card."""
    with index._cursor() as cur:
        cur.execute("SELECT * FROM cards WHERE folder = ? AND file = ?", (folder, filename))
        row = cur.fetchone()
        if row:
            entry = index._row_to_entry(row)
            metadata = index.extract_metadata(entry.path)
            return {
                "entry": asdict(entry),
                "full_metadata": metadata
            }

    raise HTTPException(status_code=404, detail="Card not found")


@app.get("/cards/{folder}/{filename}")
async def serve_card_image(folder: str, filename: str):
    """Serve the actual card PNG file."""
    with index._cursor() as cur:
        cur.execute("SELECT path FROM cards WHERE folder = ? AND file = ?", (folder, filename))
        row = cur.fetchone()
        if row:
            return FileResponse(row[0], media_type="image/png")

    raise HTTPException(status_code=404, detail="Card not found")


@app.get("/api/stats")
async def get_stats():
    """Get index statistics."""
    stats = index.get_stats()
    tags = index.get_all_tags()
    duplicates = index.get_duplicates()
    image_duplicates = index.get_image_duplicates()

    return {
        "total_cards": stats["total_cards"],
        "nsfw_count": stats["nsfw_count"],
        "sfw_count": stats["sfw_count"],
        "unique_creators": stats["unique_creators"],
        "unique_tags": len(tags),
        "quarantined": index.get_quarantine_count(),
        "content_duplicate_groups": len([p for p in duplicates.values() if len(p) > 1]),
        "image_duplicate_groups": len([p for p in image_duplicates.values() if len(p) > 1]),
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "top_tags": tags[:100],
        "top_creators": stats["top_creators"],
        "folders": stats["folders"]
    }


@app.get("/api/tags")
async def get_tags():
    """Get all unique tags with counts."""
    return {"tags": index.get_all_tags()}


@app.post("/api/checkpoint")
async def force_checkpoint():
    """Force a WAL checkpoint and return database verification."""
    result = index.checkpoint()
    logger.info(f"CHECKPOINT: {result}")
    return result


@app.post("/api/fix-unnamed")
async def fix_unnamed_cards():
    """Re-index only cards with empty or unknown names - updates PNG metadata AND database."""
    with index._cursor() as cur:
        # Find cards with empty/unknown names
        cur.execute("""
            SELECT path, file FROM cards
            WHERE name = '' OR name IS NULL OR LOWER(name) = 'unknown' OR LOWER(name) = 'unnamed'
            OR name = file OR name = REPLACE(file, '.png', '') OR name = REPLACE(file, '.card.png', '')
        """)
        unnamed_cards = cur.fetchall()

    total = len(unnamed_cards)
    if total == 0:
        return {"message": "No unnamed cards found", "fixed": 0}

    logger.info(f"FIX-UNNAMED: Found {total} cards to fix")

    fixed = 0
    metadata_updated = 0
    failed = 0

    for i, (path, filename) in enumerate(unnamed_cards):
        if i % 100 == 0:
            logger.info(f"FIX-UNNAMED: Progress {i}/{total}")

        if not os.path.exists(path):
            failed += 1
            continue

        try:
            # Parse name from filename
            parsed_name, parsed_creator = parse_name_from_filename(filename)

            if not parsed_name or parsed_name == filename.replace('.png', '').replace('.card', ''):
                failed += 1
                continue

            # Read current metadata
            metadata = index.extract_metadata(path)
            if not metadata:
                failed += 1
                continue

            # Update metadata with parsed name/creator
            data = metadata.get("data", metadata)
            current_name = data.get("name", "").strip()
            current_creator = data.get("creator", "").strip()

            updated = False
            if not current_name or current_name.lower() in ["", "unknown", "unnamed"]:
                data["name"] = parsed_name
                updated = True

            if not current_creator or current_creator.lower() in ["", "unknown"]:
                data["creator"] = parsed_creator
                updated = True

            # Write updated metadata back to PNG
            if updated:
                if "data" in metadata:
                    metadata["data"] = data
                else:
                    metadata = data

                if index.write_metadata(path, metadata):
                    metadata_updated += 1
                else:
                    logger.warning(f"FIX-UNNAMED: Failed to write metadata for {path}")

            # Re-index the card (will now pick up the updated metadata)
            entry = index.index_card(path, delete_prohibited=False)
            if entry and entry.name == parsed_name:
                fixed += 1
            else:
                failed += 1

        except Exception as e:
            logger.error(f"FIX-UNNAMED: Error processing {path}: {e}")
            failed += 1

    logger.info(f"FIX-UNNAMED: Complete. Fixed {fixed}, PNG metadata updated {metadata_updated}, failed {failed}")
    return {
        "message": f"Fixed {fixed} unnamed cards, updated {metadata_updated} PNG files",
        "total_found": total,
        "fixed": fixed,
        "metadata_updated": metadata_updated,
        "failed": failed
    }


@app.post("/api/fix-unnamed-lorebooks")
async def fix_unnamed_lorebooks():
    """Check ALL lorebooks and fix any where the name doesn't match what's parsed from filename."""
    lorebook_extensions = ['.lorebook_sillytavern.json', '.lorebook.json', '.json']

    with index._cursor() as cur:
        cur.execute("SELECT id, file_path, file, name FROM lorebooks")
        all_lorebooks = cur.fetchall()

    total = len(all_lorebooks)
    logger.info(f"FIX-UNNAMED-LOREBOOKS: Checking {total} lorebooks")

    checked = 0
    fixed = 0
    metadata_updated = 0
    skipped = 0
    failed = 0
    mismatches = []

    for i, (lb_id, file_path, filename, current_name) in enumerate(all_lorebooks):
        checked += 1
        if i % 50 == 0:
            logger.info(f"FIX-UNNAMED-LOREBOOKS: Progress {i}/{total}")

        if not os.path.exists(file_path):
            failed += 1
            continue

        try:
            # Parse expected name from filename
            parsed_name, parsed_creator = parse_name_from_filename(filename, lorebook_extensions)

            # Skip if we couldn't parse a meaningful name
            if not parsed_name:
                skipped += 1
                continue

            # Compare current name vs parsed name
            current_clean = (current_name or "").strip()
            parsed_clean = parsed_name.strip()

            # Check if they match (case-insensitive)
            if current_clean.lower() == parsed_clean.lower():
                skipped += 1
                continue

            # They don't match - log and fix
            logger.info(f"FIX-UNNAMED-LOREBOOKS: Mismatch - '{current_clean}' -> '{parsed_clean}' ({filename})")
            mismatches.append({
                "file": filename,
                "old_name": current_clean,
                "new_name": parsed_clean
            })

            # Update the JSON file with the new name
            if index.write_lorebook_metadata(file_path, name=parsed_clean):
                metadata_updated += 1

            # Re-parse and re-index
            lorebook_data = index._parse_lorebook(file_path)
            if lorebook_data:
                index._index_lorebook(lorebook_data)
                fixed += 1
            else:
                failed += 1

        except Exception as e:
            logger.error(f"FIX-UNNAMED-LOREBOOKS: Error processing {file_path}: {e}")
            failed += 1

    logger.info(f"FIX-UNNAMED-LOREBOOKS: Complete. Checked {checked}, fixed {fixed}, skipped {skipped}, failed {failed}")
    return {
        "message": f"Checked {total} lorebooks, fixed {fixed} names, updated {metadata_updated} JSON files",
        "total_checked": total,
        "fixed": fixed,
        "metadata_updated": metadata_updated,
        "skipped": skipped,
        "failed": failed,
        "mismatches": mismatches[:50]  # Show first 50 mismatches
    }


@app.get("/api/debug/paths")
async def debug_paths(
    prefix: str = Query(None, description="Path prefix to search"),
    limit: int = Query(100, ge=1, le=500)
):
    """Debug endpoint to check cards by path prefix."""
    with index._cursor() as cur:
        if prefix:
            cur.execute(
                "SELECT path, folder, file, indexed_at FROM cards WHERE path LIKE ? ORDER BY indexed_at DESC LIMIT ?",
                (f"{prefix}%", limit)
            )
        else:
            cur.execute(
                "SELECT path, folder, file, indexed_at FROM cards ORDER BY indexed_at DESC LIMIT ?",
                (limit,)
            )
        cards = [{"path": row[0], "folder": row[1], "file": row[2], "indexed_at": row[3]} for row in cur.fetchall()]

        # Also get count by folder prefix
        if prefix:
            cur.execute("SELECT COUNT(*) FROM cards WHERE path LIKE ?", (f"{prefix}%",))
        else:
            cur.execute("SELECT COUNT(*) FROM cards")
        total = cur.fetchone()[0]

    return {
        "prefix": prefix,
        "total_matching": total,
        "sample": cards,
        "card_dirs": CARD_DIRS,
        "db_path": index.db_path
    }


@app.get("/api/quarantine")
async def get_quarantine():
    """Get list of quarantined cards for manual review."""
    return {
        "total_quarantined": index.get_quarantine_count(),
        "cards": index.get_quarantine(100)
    }


@app.post("/api/quarantine/approve")
async def approve_quarantine_card(path: str = Query(...)):
    """Approve a quarantined card - removes from quarantine, keeps in index."""
    with index._cursor() as cur:
        cur.execute("DELETE FROM quarantine WHERE path = ?", (path,))
        if cur.rowcount > 0:
            return {"success": True, "path": path, "action": "approved"}
        else:
            raise HTTPException(status_code=404, detail="Card not found in quarantine")


@app.delete("/api/quarantine/delete-all")
async def delete_all_quarantined():
    """Delete all cards in quarantine."""
    paths = index.get_all_quarantine_paths()
    deleted = 0
    failed_paths = []
    
    for path in paths:
        if index.delete_card(path):
            deleted += 1
        else:
            failed_paths.append(path)
    
    # Clean up quarantine records for paths that no longer exist
    if failed_paths:
        for path in failed_paths:
            if not os.path.exists(path):
                try:
                    with index._cursor() as cur:
                        cur.execute("DELETE FROM quarantine WHERE path = ?", (path,))
                except Exception as e:
                    logger.error(f"Failed to clean quarantine record for {path}: {e}")
    
    return {"success": True, "deleted_count": deleted, "failed_count": len(failed_paths)}


# Keep old endpoint for backwards compatibility
@app.get("/api/prohibited")
async def get_prohibited_legacy():
    """Legacy endpoint - use /api/quarantine instead."""
    return await get_quarantine()


@app.delete("/api/prohibited/delete")
async def delete_prohibited_card(path: str = Query(...)):
    """Manually delete a prohibited card after review."""
    if index.delete_card(path):
        return {"success": True, "deleted": path}
    else:
        raise HTTPException(status_code=404, detail="Card not found")


@app.get("/api/duplicates")
async def get_duplicates():
    """Get list of detected duplicate cards."""

    def get_card_info(path: str) -> dict:
        entry = index.get_card_by_path(path)
        if entry:
            return {
                "path": path,
                "name": entry.name,
                "creator": entry.creator,
                "folder": entry.folder,
                "file": entry.file,
                "nsfw": entry.nsfw
            }
        return {"path": path, "name": Path(path).stem, "creator": "Unknown", "folder": "", "file": Path(path).name, "nsfw": False}

    # Content-based duplicates
    content_dupes = []
    for content_hash, paths in index.get_duplicates().items():
        if len(paths) > 1 and not index.is_duplicate_ignored(paths):
            content_dupes.append({
                "type": "content",
                "hash": content_hash,
                "count": len(paths),
                "cards": [get_card_info(p) for p in paths]
            })

    # Image-based duplicates
    image_dupes = []
    for image_hash, paths in index.get_image_duplicates().items():
        if len(paths) > 1:
            cards_info = [(p, get_card_info(p)) for p in paths if os.path.exists(p)]
            if len(cards_info) >= 2 and not index.is_duplicate_ignored([p for p, _ in cards_info]):
                # Verify name similarity
                filtered_cards = [cards_info[0]]
                base_name = cards_info[0][1]["name"]
                for p, info in cards_info[1:]:
                    if name_similarity(base_name, info["name"]) > 0.3:
                        filtered_cards.append((p, info))

                if len(filtered_cards) >= 2:
                    image_dupes.append({
                        "type": "image",
                        "hash": image_hash,
                        "count": len(filtered_cards),
                        "cards": [info for _, info in filtered_cards]
                    })

    all_dupes = content_dupes + image_dupes
    all_dupes.sort(key=lambda x: x["count"], reverse=True)

    return {
        "content_duplicate_groups": len(content_dupes),
        "image_duplicate_groups": len(image_dupes),
        "total_duplicate_groups": len(all_dupes),
        "total_duplicate_files": sum(d["count"] - 1 for d in all_dupes),
        "detect_enabled": DETECT_DUPLICATES,
        "image_hash_enabled": IMAGE_HASH_AVAILABLE,
        "duplicates": all_dupes[:100]
    }


@app.get("/api/cards/similar")
async def find_similar_cards(
    path: str = Query(None, description="Path to card"),
    folder: str = Query(None, description="Folder of card"),
    file: str = Query(None, description="Filename of card"),
    threshold: int = Query(18, description="Image hash threshold")
):
    """Find cards similar to a given card."""
    source_entry = None
    source_path = path

    if path:
        source_entry = index.get_card_by_path(path)
    elif folder and file:
        with index._cursor() as cur:
            cur.execute("SELECT * FROM cards WHERE folder = ? AND file = ?", (folder, file))
            row = cur.fetchone()
            if row:
                source_entry = index._row_to_entry(row)
                source_path = source_entry.path

    if not source_entry:
        raise HTTPException(status_code=404, detail="Source card not found")

    similar = []
    source_hash = index.image_hash_objects.get(source_path)

    # Get all cards for comparison
    all_cards = index.get_all_cards()

    for card_path, entry in all_cards.items():
        if card_path == source_path:
            continue

        similarity_score = 0
        match_reasons = []

        name_sim = name_similarity(source_entry.name, entry.name)
        if name_sim > 0.3:
            similarity_score += name_sim * 50
            match_reasons.append(f"name ({int(name_sim*100)}%)")

        if source_hash and IMAGE_HASH_AVAILABLE:
            card_hash = index.image_hash_objects.get(card_path)
            if card_hash:
                distance = source_hash - card_hash
                if distance <= threshold:
                    img_score = (threshold - distance) / threshold * 50
                    similarity_score += img_score
                    match_reasons.append(f"image (dist={distance})")

        if source_entry.creator.lower() == entry.creator.lower() and source_entry.creator.lower() != "unknown":
            similarity_score += 10
            match_reasons.append("same creator")

        if similarity_score > 20:
            similar.append({
                "path": card_path,
                "folder": entry.folder,
                "file": entry.file,
                "name": entry.name,
                "creator": entry.creator,
                "nsfw": entry.nsfw,
                "score": round(similarity_score, 1),
                "reasons": match_reasons
            })

    similar.sort(key=lambda x: x["score"], reverse=True)

    return {
        "source": {
            "path": source_path,
            "name": source_entry.name,
            "folder": source_entry.folder,
            "file": source_entry.file
        },
        "similar_count": len(similar),
        "similar": similar[:50]
    }


@app.post("/api/cards/upload")
async def upload_card(
    file: UploadFile = File(..., description="PNG character card file"),
    folder: str = Form(default="Uploads", description="Subfolder to save to")
):
    """Upload a character card to the server."""
    if not file.filename.lower().endswith('.png'):
        raise HTTPException(status_code=400, detail="Only PNG files are supported")

    if not CARD_DIRS or not CARD_DIRS[0]:
        raise HTTPException(status_code=500, detail="No card directories configured")

    base_dir = CARD_DIRS[0]
    safe_folder = "".join(c for c in folder if c.isalnum() or c in " -_").strip() or "Uploads"
    upload_dir = os.path.join(base_dir, safe_folder)

    try:
        os.makedirs(upload_dir, exist_ok=True)
        safe_filename = "".join(c for c in file.filename if c.isalnum() or c in " -_.").strip()
        if not safe_filename.lower().endswith('.png'):
            safe_filename += '.png'

        filepath = os.path.join(upload_dir, safe_filename)

        if os.path.exists(filepath):
            base, ext = os.path.splitext(safe_filename)
            counter = 1
            while os.path.exists(filepath):
                safe_filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(upload_dir, safe_filename)
                counter += 1

        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"Uploaded card: {filepath}")

        entry = index.index_card(filepath, delete_prohibited=True)
        if entry:
            return {
                "success": True,
                "path": filepath,
                "folder": safe_folder,
                "file": safe_filename,
                "name": entry.name,
                "indexed": True
            }
        else:
            if os.path.exists(filepath):
                os.remove(filepath)
                return {"success": False, "detail": "Invalid character card: no embedded metadata found"}
            else:
                return {"success": False, "detail": "Card rejected: prohibited content detected"}

    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/cards/delete")
async def delete_card(path: str = Query(..., description="Full path to the card file")):
    """Delete a single card file."""
    if not path:
        raise HTTPException(status_code=400, detail="Path required")

    if index.delete_card(path):
        return {"success": True, "deleted": path}
    else:
        raise HTTPException(status_code=404, detail="File not found or delete failed")


@app.post("/api/duplicates/ignore")
async def ignore_duplicate_group(paths: List[str] = Query(..., description="Paths in the duplicate group")):
    """Mark a group of cards as NOT duplicates."""
    if len(paths) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 paths")

    index.ignore_duplicate(paths)
    logger.info(f"Marked as non-duplicate: {paths}")
    return {"status": "Marked as non-duplicate", "paths": paths}


@app.delete("/api/duplicates/clean")
async def clean_duplicates(
    keep: str = Query("first", description="Which to keep: 'first' or 'largest'"),
    type: str = Query("all", description="Which duplicates: 'content', 'image', or 'all'"),
    check_description: bool = Query(False, description="Only delete if descriptions match")
):
    """Delete duplicate files, keeping one copy of each."""
    if not DETECT_DUPLICATES:
        raise HTTPException(status_code=400, detail="Duplicate detection is disabled")

    deleted = []
    already_deleted = set()

    def clean_group(paths: List[str]):
        if len(paths) <= 1:
            return
        valid_paths = [p for p in paths if p not in already_deleted and os.path.exists(p)]
        if len(valid_paths) <= 1:
            return

        # If check_description is True, only process if ALL descriptions match
        if check_description:
            descriptions = []
            for path in valid_paths:
                entry = index.get_card_by_path(path)
                if entry:
                    # Use description_preview from database
                    descriptions.append(entry.description_preview or '')
                else:
                    # Try to extract from metadata as fallback
                    metadata = index.extract_metadata(path)
                    if metadata and 'data' in metadata:
                        desc = metadata['data'].get('description', '')
                        descriptions.append(desc or '')
                    else:
                        descriptions.append('')
            
            # If descriptions differ, skip this group
            # Note: Empty descriptions ('') are treated as matching each other
            if len(set(descriptions)) > 1:
                return

        if keep == "largest":
            paths_with_size = [(p, os.path.getsize(p)) for p in valid_paths]
            paths_with_size.sort(key=lambda x: x[1], reverse=True)
            delete_paths = [p for p, _ in paths_with_size[1:]]
        else:
            delete_paths = valid_paths[1:]

        for path in delete_paths:
            if index.delete_card(path):
                deleted.append(path)
                already_deleted.add(path)
                logger.info(f"Deleted duplicate: {path}")

    if type in ["all", "content"]:
        for paths in index.get_duplicates().values():
            clean_group(paths)

    if type in ["all", "image"]:
        for paths in index.get_image_duplicates().values():
            clean_group(paths)

    return {"deleted_count": len(deleted), "deleted_files": deleted[:100]}


# Nextcloud scan tracking
nextcloud_scan_status = {"running": False, "last_scan": None, "last_result": None}


@app.post("/api/nextcloud/scan")
async def trigger_nextcloud_scan(user: str = Query(None, description="Nextcloud user to scan")):
    """Trigger a Nextcloud file scan."""
    global nextcloud_scan_status

    if nextcloud_scan_status["running"]:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    scan_user = user or NEXTCLOUD_USER
    nextcloud_scan_status["running"] = True

    try:
        logger.info(f"Starting Nextcloud scan for user: {scan_user}")
        result = subprocess.run(
            ["sudo", "nextcloud.occ", "files:scan", scan_user],
            capture_output=True, text=True, timeout=3600
        )

        nextcloud_scan_status["last_scan"] = datetime.utcnow().isoformat()
        nextcloud_scan_status["last_result"] = {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else ""
        }

        return nextcloud_scan_status["last_result"]

    except subprocess.TimeoutExpired:
        nextcloud_scan_status["last_result"] = {"success": False, "error": "Scan timed out"}
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as e:
        nextcloud_scan_status["last_result"] = {"success": False, "error": str(e)}
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        nextcloud_scan_status["running"] = False


@app.get("/api/nextcloud/status")
async def get_nextcloud_status():
    """Get Nextcloud scan status."""
    return nextcloud_scan_status


@app.get("/api/index/status")
async def get_index_status():
    """Get index scan status."""
    return {
        "cards_indexed": index.get_card_count(),
        "scan_running": index.scan_status["running"],
        "scan_progress": index.scan_status["progress"],
        "scan_total": index.scan_status["total"],
        "last_scan": index.scan_status["last_scan"],
        "watcher": watcher_status
    }


@app.post("/api/index/rescan")
async def trigger_rescan():
    """Trigger a full rescan of all directories."""
    if index.scan_status["running"]:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    asyncio.create_task(background_scan())
    return {"status": "Rescan started"}


@app.post("/api/index/save")
async def save_index_now():
    """Manually save the index (no-op for SQLite, auto-persists)."""
    return {"status": "Index auto-saved (SQLite)", "cards": index.get_card_count()}


# ===== IMPORT ENDPOINTS =====

import_status = {
    "running": False,
    "phase": "",
    "progress": 0,
    "total": 0,
    "source_dir": None,
    "skipped_existing": 0,
    "skipped_duplicates": 0,
    "new_cards": 0,
    "prohibited": 0,
    "quarantine": 0,
    "errors": 0,
    "current_file": ""
}


@app.post("/api/import/scan")
async def scan_for_import(
    source_dir: str = Query(..., description="Source directory to scan"),
    recursive: bool = Query(True, description="Scan subdirectories")
):
    """
    Scan a source directory for cards to import.
    Returns categorized results: new, duplicates, prohibited, quarantine.
    Does NOT modify any files.
    """
    global import_status
    import asyncio

    if import_status["running"]:
        raise HTTPException(status_code=409, detail="Import scan already in progress")

    if not os.path.exists(source_dir):
        raise HTTPException(status_code=404, detail=f"Directory not found: {source_dir}")

    # Reset and start status tracking
    import_status.update({
        "running": True,
        "phase": "starting",
        "progress": 0,
        "total": 0,
        "source_dir": source_dir,
        "skipped_existing": 0,
        "skipped_duplicates": 0,
        "new_cards": 0,
        "prohibited": 0,
        "quarantine": 0,
        "errors": 0,
        "current_file": ""
    })

    def progress_callback(phase, current, total, details):
        import_status.update({
            "phase": phase,
            "progress": current,
            "total": total,
            "current_file": details.get("current_file", ""),
            "skipped_existing": details.get("skipped_existing", import_status["skipped_existing"]),
            "skipped_duplicates": details.get("skipped_duplicates", import_status["skipped_duplicates"]),
            "new_cards": details.get("new_cards", import_status["new_cards"]),
            "prohibited": details.get("prohibited", import_status["prohibited"]),
            "quarantine": details.get("quarantine", import_status["quarantine"]),
            "errors": details.get("errors", import_status["errors"]),
            "message": details.get("message", "")
        })

    def do_scan():
        return index.scan_source_for_import(source_dir, recursive=recursive,
                                            progress_callback=progress_callback)

    try:
        # Run scan in thread pool to allow status polling
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, do_scan)

        # Store full results in import_status for pagination/continued access
        import_status["results"] = results

        return {
            "success": True,
            "source_dir": source_dir,
            "total_files": results["total_files"],
            "skipped_existing": results.get("skipped_existing", 0),
            "skipped_duplicates": results.get("skipped_duplicates", 0),
            "files_processed": results.get("files_to_process", results["total_files"]),
            "summary": {
                "new_cards": len(results["new_cards"]),
                "skipped_duplicates": results.get("skipped_duplicates", 0),
                "prohibited": len(results["prohibited"]),
                "quarantine": len(results["quarantine"]),
                "errors": len(results["errors"])
            },
            "new_cards": results["new_cards"],  # Return ALL cards
            "prohibited": results["prohibited"],
            "quarantine": results["quarantine"],
            "errors": results["errors"]
        }
    except Exception as e:
        logger.error(f"Import scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        import_status["running"] = False


@app.get("/api/import/status")
async def get_import_status():
    """Get current import scan status."""
    return import_status


@app.get("/api/import/last-scan")
async def get_last_import_scan(source_dir: str = Query(None, description="Filter by source directory")):
    """Get results from the last import scan."""
    results = index.get_last_import_scan(source_dir)
    if results:
        return results
    raise HTTPException(status_code=404, detail="No previous scan found")


@app.post("/api/import/execute")
async def execute_import(
    source_paths: List[str] = Query(..., description="List of source file paths to import"),
    destination_folder: str = Query(None, description="Destination folder name (optional)")
):
    """
    Execute import of specified cards.
    Copies files from source to destination and indexes them.
    Does NOT delete source files.
    """
    if not source_paths:
        raise HTTPException(status_code=400, detail="No source paths provided")

    results = index.execute_import(source_paths, destination_folder)

    # Get current database count for verification
    stats = index.get_stats()

    return {
        "success": True,
        "imported_count": len(results["imported"]),
        "failed_count": len(results["failed"]),
        "skipped_count": len(results["skipped"]),
        "imported": results["imported"],
        "failed": results["failed"],
        "skipped": results["skipped"],
        "total_cards_in_db": stats["total_cards"]
    }


@app.get("/api/import/quarantine")
async def get_quarantine(
    status: str = Query(None, description="Filter by status: pending, reviewed"),
    limit: int = Query(100, ge=1, le=500)
):
    """Get cards in quarantine awaiting review."""
    cards = index.get_quarantine_list(status=status, limit=limit)
    return {
        "count": len(cards),
        "cards": cards
    }


@app.post("/api/import/quarantine/review")
async def review_quarantine(
    source_path: str = Query(..., description="Source path of quarantined card"),
    decision: str = Query(..., description="Decision: approve or reject")
):
    """Review a quarantined card - approve or reject for import."""
    if decision not in ["approve", "reject"]:
        raise HTTPException(status_code=400, detail="Decision must be 'approve' or 'reject'")

    success = index.review_quarantine_card(source_path, decision)
    if not success:
        raise HTTPException(status_code=404, detail="Card not found in quarantine")

    # If approved, import the card
    if decision == "approve":
        results = index.execute_import([source_path])
        return {
            "status": "approved and imported",
            "import_result": results
        }

    return {"status": "rejected", "source_path": source_path}


@app.post("/api/import/quarantine/bulk-review")
async def bulk_review_quarantine(
    decision: str = Query(..., description="Decision: approve or reject"),
    source_paths: List[str] = Query(None, description="Specific paths (if not provided, applies to all pending)")
):
    """Bulk review quarantined cards."""
    if decision not in ["approve", "reject"]:
        raise HTTPException(status_code=400, detail="Decision must be 'approve' or 'reject'")

    # Get cards to review
    if source_paths:
        paths_to_review = source_paths
    else:
        pending = index.get_quarantine_list(status="pending", limit=500)
        paths_to_review = [card["source_path"] for card in pending]

    results = {"reviewed": 0, "imported": 0, "failed": 0}

    for path in paths_to_review:
        if index.review_quarantine_card(path, decision):
            results["reviewed"] += 1
            if decision == "approve":
                import_result = index.execute_import([path])
                results["imported"] += len(import_result["imported"])
                results["failed"] += len(import_result["failed"])

    return results


# ===== LOREBOOK ENDPOINTS =====

@app.get("/api/lorebooks")
async def search_lorebooks(
    q: str = Query(None, description="Search query"),
    topics: str = Query(None, description="Filter by topics (comma-separated)"),
    creator: str = Query(None, description="Filter by creator"),
    nsfw: bool = Query(None, description="Filter by NSFW status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Search and browse lorebooks."""
    topic_list = [t.strip() for t in topics.split(",")] if topics else None

    lorebooks, total = index.search_lorebooks(
        query=q,
        topics=topic_list,
        creator=creator,
        nsfw=nsfw,
        limit=limit,
        offset=offset
    )

    # Parse topics JSON for response
    for lb in lorebooks:
        try:
            lb["topics"] = json.loads(lb.get("topics", "[]"))
        except:
            lb["topics"] = []

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(lorebooks),
        "lorebooks": lorebooks
    }


@app.get("/api/lorebooks/stats")
async def get_lorebook_stats():
    """Get lorebook statistics."""
    stats = index.get_lorebook_stats()
    stats["configured_dirs"] = LOREBOOK_DIRS
    return stats


@app.get("/api/lorebooks/topics")
async def get_lorebook_topics():
    """Get all lorebook topics with counts."""
    return {"topics": index.get_lorebook_topics()}


@app.get("/api/lorebooks/{lorebook_id}")
async def get_lorebook(lorebook_id: int):
    """Get a lorebook by ID with full content."""
    lorebook = index.get_lorebook(lorebook_id)
    if not lorebook:
        raise HTTPException(status_code=404, detail="Lorebook not found")

    try:
        lorebook["topics"] = json.loads(lorebook.get("topics", "[]"))
    except:
        lorebook["topics"] = []

    return lorebook


@app.get("/lorebooks/{folder:path}/{filename}")
async def serve_lorebook_file(folder: str, filename: str):
    """Serve a lorebook JSON file for SillyTavern import."""
    # Find the lorebook by folder/filename
    with index._cursor() as cur:
        cur.execute(
            "SELECT file_path FROM lorebooks WHERE folder = ? AND file = ?",
            (folder, filename)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Lorebook not found")

        file_path = row[0]

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Lorebook file not found")

    return FileResponse(
        file_path,
        media_type="application/json",
        filename=filename
    )


@app.post("/api/lorebooks/scan")
async def scan_lorebooks(
    source_dir: str = Query(None, description="Directory to scan (uses LOREBOOK_DIRS if not specified)"),
    recursive: bool = Query(True, description="Scan subdirectories")
):
    """Scan a directory for lorebook files and index them."""
    dirs_to_scan = []

    if source_dir:
        dirs_to_scan = [source_dir]
    elif LOREBOOK_DIRS:
        dirs_to_scan = LOREBOOK_DIRS
    else:
        raise HTTPException(status_code=400, detail="No source directory specified and LOREBOOK_DIRS not configured")

    all_results = {
        "total_files": 0,
        "indexed": 0,
        "skipped": 0,
        "errors": []
    }

    for dir_path in dirs_to_scan:
        if not os.path.exists(dir_path):
            all_results["errors"].append(f"Directory not found: {dir_path}")
            continue

        results = index.scan_lorebooks(dir_path, recursive=recursive)
        all_results["total_files"] += results["total_files"]
        all_results["indexed"] += results["indexed"]
        all_results["skipped"] += results["skipped"]
        all_results["errors"].extend(results["errors"])

    return {
        "success": True,
        "directories": dirs_to_scan,
        "total_files": all_results["total_files"],
        "indexed": all_results["indexed"],
        "skipped": all_results["skipped"],
        "errors": all_results["errors"][:20]
    }


@app.delete("/api/lorebooks/clear")
async def clear_lorebooks():
    """Clear all lorebooks from the index."""
    with index._cursor() as cur:
        cur.execute("DELETE FROM lorebooks")
        deleted = cur.rowcount
    return {"success": True, "deleted": deleted}


@app.delete("/api/lorebooks/{lorebook_id}")
async def delete_lorebook(lorebook_id: int):
    """Delete a lorebook from the index."""
    with index._cursor() as cur:
        cur.execute("DELETE FROM lorebooks WHERE id = ?", (lorebook_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Lorebook not found")
    return {"success": True}


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
