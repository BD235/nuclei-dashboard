import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DB_PATH = Path(__file__).parent / "scans.db"

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Menyediakan koneksi database dengan optimasi performa dan isolasi transaksi."""
    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=10.0,
        isolation_level=None  # Mode autocommit terkontrol
    )
    conn.row_factory = sqlite3.Row
    
    # Optimasi performa dan konkurensi SQLite
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    
    try:
        yield conn
    finally:
        conn.close()

def init_db() -> None:
    """Menginisialisasi skema tabel relasional dan indeks performa."""
    with get_db() as conn:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT CHECK(status IN ('queued', 'running', 'completed', 'failed')) DEFAULT 'queued',
                total_findings INTEGER DEFAULT 0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                error_message TEXT
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                template_id TEXT NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                matched_at TEXT NOT NULL,
                description TEXT,
                raw_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
            """)

            # Indeks untuk query filtering dan aggregation cepat
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")

            # Tabel Allowlist target
            conn.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                label TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_allowlist_target ON allowlist(target);")

            # Tabel Audit Log
            conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                target TEXT,
                source_ip TEXT,
                detail TEXT
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);")

            # Seeding default allowlist jika masih kosong
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM allowlist;")
            count = cursor.fetchone()["cnt"]
            if count == 0:
                default_targets = [
                    ("http://localhost:3000", "OWASP Juice Shop (Host)"),
                    ("http://juice-shop:3000", "OWASP Juice Shop (Docker Network)"),
                    ("http://testphp.vulnweb.com", "Acuart TestPHP (Demo Lab)")
                ]
                conn.executemany(
                    "INSERT INTO allowlist (target, label) VALUES (?, ?);",
                    default_targets
                )

            # Bersihkan scan berstatus 'running' / 'queued' yang tertinggal akibat restart server
            conn.execute("""
            UPDATE scans
            SET status = 'failed',
                error_message = 'Proses terhenti akibat restart server/container.',
                finished_at = CURRENT_TIMESTAMP
            WHERE status IN ('running', 'queued');
            """)


def log_audit_event(
    action: str,
    target: str | None = None,
    source_ip: str | None = None,
    detail: str | None = None
) -> None:
    """Mencatat aktivitas dan anomali keamanan ke dalam tabel audit_log."""
    try:
        with get_db() as conn:
            with conn:
                conn.execute(
                    "INSERT INTO audit_log (action, target, source_ip, detail) VALUES (?, ?, ?, ?);",
                    (action, target, source_ip, detail)
                )
    except Exception as exc:
        # Menghindari crash aplikasi jika pencatatan audit log menemui kendala I/O
        print(f"[AUDIT LOG ERROR] Gagal menulis log audit: {exc}")


def is_target_in_allowlist(base_target: str) -> bool:
    """Mengecek apakah URL target dasar terdaftar di tabel allowlist."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM allowlist WHERE target = ? COLLATE NOCASE;",
            (base_target,)
        ).fetchone()
        return row is not None