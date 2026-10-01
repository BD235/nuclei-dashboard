import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from database import get_db, init_db, is_target_in_allowlist, log_audit_event
from runner import execute_scan

PROFILES_PATH = Path(__file__).parent / "profiles.json"
API_KEY = os.getenv("API_KEY", "nuclei-secret-key-2024")

def load_profiles() -> Dict[str, Any]:
    if not PROFILES_PATH.exists():
        raise FileNotFoundError("Berkas profiles.json tidak ditemukan.")
    with open(PROFILES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

PROFILES = load_profiles()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

# Inisialisasi Rate Limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Nuclei Vulnerability Scanner API",
    version="1.2.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware CORS untuk antarmuka web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Keamanan & Autentikasi (API Key) ---

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(
    request: Request,
    key_header: Optional[str] = Security(api_key_header)
) -> str:
    """Memvalidasi header X-API-Key menggunakan perbandingan waktu konstan (constant-time)."""
    client_ip = request.client.host if request.client else "unknown"
    if not key_header or not secrets.compare_digest(key_header, API_KEY):
        log_audit_event(
            action="auth_failed",
            target=str(request.url.path),
            source_ip=client_ip,
            detail="Header X-API-Key tidak valid atau tidak disertakan"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key tidak valid atau tidak disertakan pada header X-API-Key."
        )
    return key_header

# --- Validasi & Normalisasi Target Universal (Web, API, Network) ---

def normalize_target(target: str) -> str:
    """
    Menormalisasi target pemindaian secara aman dan deterministik.
    Mendukung:
    1. Web/API URL: http://... atau https://...
    2. Jaringan/Host:Port: 192.168.1.1:22, target.local:445, localhost:6379
    """
    raw = str(target).strip()
    if not raw:
        raise ValueError("Target tidak boleh kosong.")

    # 1. Cek apakah berformat URL HTTP/HTTPS
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        if not parsed.netloc:
            raise ValueError("Format URL tidak valid.")
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        # Pertahankan path jika ada (misal /v1 atau /api)
        if path:
            return f"{scheme}://{netloc}{path}"
        return f"{scheme}://{netloc}"

    # 2. Cek apakah berformat Host[:Port] untuk pengujian Jaringan
    # Regex: hostname/IP opsional port
    host_port_pattern = r"^[a-zA-Z0-9_\-\.]+(:\d{1,5})?$"
    if re.match(host_port_pattern, raw):
        return raw.lower()

    # 3. Default jika tanpa protokol tapi tampak seperti domain/url web
    if "." in raw and not ":" in raw:
        return f"http://{raw.lower()}"

    raise ValueError("Target harus berupa URL HTTP/HTTPS (Web/API) atau Host:Port (Jaringan).")

# --- Skema Validasi Input/Output (Pydantic v2) ---

class ScanCreateRequest(BaseModel):
    target: str
    profile: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return normalize_target(v)

class ScanResponse(BaseModel):
    scan_id: str
    target: str
    profile: str
    status: str
    total_findings: int
    started_at: Optional[str]
    finished_at: Optional[str]
    error_message: Optional[str]

class FindingResponse(BaseModel):
    id: int
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: Optional[str]

class ReportSummary(BaseModel):
    scan_id: str
    target: str
    status: str
    total_findings: int
    severity_breakdown: Dict[str, int]

class AllowlistEntry(BaseModel):
    id: int
    target: str
    label: Optional[str] = ""
    added_at: str

class AllowlistCreateRequest(BaseModel):
    target: str
    label: Optional[str] = ""

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return normalize_target(v)

class AuditLogEntry(BaseModel):
    id: int
    timestamp: str
    action: str
    target: Optional[str]
    source_ip: Optional[str]
    detail: Optional[str]

# --- Endpoint API: Profiles ---

@app.get("/api/profiles", tags=["Configuration"])
def list_profiles() -> Dict[str, Any]:
    """Mengambil daftar profil pemindaian terarah (Web, API, Network)."""
    # Muat ulang konfigurasi profiles untuk memastikan update dinamis
    current_profiles = load_profiles()
    return {
        key: {
            "name": val["name"],
            "category": val.get("category", "web"),
            "description": val["description"],
            "severity": val["severity"],
            "tags": val.get("tags", []),
            "rate_limit": val.get("rate_limit", 50),
            "concurrency": val.get("concurrency", 10),
            "automatic_scan": val.get("automatic_scan", False)
        } for key, val in current_profiles.items()
    }

# --- Endpoint API: Allowlist (CRUD) ---

@app.get("/api/allowlist", response_model=List[AllowlistEntry], tags=["Allowlist"])
def list_allowlist() -> List[Dict[str, Any]]:
    """Mengambil seluruh target resmi yang terdaftar di allowlist."""
    with get_db() as conn:
        rows = conn.execute("SELECT id, target, label, added_at FROM allowlist ORDER BY added_at DESC;").fetchall()
        return [dict(row) for row in rows]

@app.post("/api/allowlist", status_code=status.HTTP_201_CREATED, response_model=AllowlistEntry, tags=["Allowlist"])
@limiter.limit("20/minute")
def add_to_allowlist(
    payload: AllowlistCreateRequest,
    request: Request,
    _auth: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """Mendaftarkan target baru ke allowlist resmi (Wajib API Key)."""
    normalized_target = payload.target
    client_ip = request.client.host if request.client else "unknown"

    try:
        with get_db() as conn:
            with conn:
                cursor = conn.execute(
                    "INSERT INTO allowlist (target, label) VALUES (?, ?);",
                    (normalized_target, payload.label.strip() if payload.label else "")
                )
                entry_id = cursor.lastrowid
                row = conn.execute("SELECT id, target, label, added_at FROM allowlist WHERE id = ?;", (entry_id,)).fetchone()

        log_audit_event(
            action="allowlist_added",
            target=normalized_target,
            source_ip=client_ip,
            detail=f"Label: {payload.label}"
        )
        return dict(row)

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target '{normalized_target}' sudah terdaftar di allowlist."
        )

@app.delete("/api/allowlist/{entry_id}", tags=["Allowlist"])
def delete_from_allowlist(
    entry_id: int,
    request: Request,
    _auth: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """Menghapus target dari allowlist resmi (Wajib API Key)."""
    client_ip = request.client.host if request.client else "unknown"

    with get_db() as conn:
        target_row = conn.execute("SELECT target FROM allowlist WHERE id = ?;", (entry_id,)).fetchone()
        if not target_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target allowlist tidak ditemukan.")
        
        target_name = target_row["target"]
        with conn:
            conn.execute("DELETE FROM allowlist WHERE id = ?;", (entry_id,))

    log_audit_event(
        action="allowlist_deleted",
        target=target_name,
        source_ip=client_ip,
        detail=f"Allowlist ID {entry_id} dihapus"
    )
    return {"message": f"Target '{target_name}' berhasil dihapus dari allowlist.", "id": entry_id}

# --- Endpoint API: Audit Logs ---

@app.get("/api/audit-logs", response_model=List[AuditLogEntry], tags=["Audit"])
def get_audit_logs(
    limit: int = 50,
    _auth: str = Depends(verify_api_key)
) -> List[Dict[str, Any]]:
    """Mengambil riwayat log audit keamanan sistem terbaru (Wajib API Key)."""
    safe_limit = max(1, min(limit, 200))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, action, target, source_ip, detail FROM audit_log ORDER BY timestamp DESC LIMIT ?;",
            (safe_limit,)
        ).fetchall()
        return [dict(row) for row in rows]

# --- Endpoint API: Scans ---

@app.post("/api/scans", status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
@limiter.limit("10/minute")
def create_scan(
    payload: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    _auth: str = Depends(verify_api_key)
) -> Dict[str, str]:
    """Mendaftarkan target baru ke antrean pemindaian latar belakang (Dilindungi Rate Limit & Allowlist)."""
    client_ip = request.client.host if request.client else "unknown"
    target_str = payload.target
    current_profiles = load_profiles()

    # 1. Validasi Profil
    if payload.profile not in current_profiles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Profil '{payload.profile}' tidak valid. Pilihan profil: {list(current_profiles.keys())}"
        )

    # 2. Validasi Allowlist
    if not is_target_in_allowlist(target_str):
        log_audit_event(
            action="scan_rejected",
            target=target_str,
            source_ip=client_ip,
            detail=f"Ditolak: target tidak terdaftar di allowlist (Profil: {payload.profile})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target '{target_str}' tidak ada di allowlist resmi. Silakan daftarkan target pada dashboard terlebih dahulu."
        )

    # 3. Pendaftaran Scan
    scan_id = str(uuid.uuid4())
    profile_data = current_profiles[payload.profile]

    with get_db() as conn:
        with conn:
            conn.execute(
                "INSERT INTO scans (scan_id, target, profile, status) VALUES (?, ?, ?, 'queued');",
                (scan_id, target_str, payload.profile)
            )

    # 4. Catat Audit Log Keberhasilan
    log_audit_event(
        action="scan_created",
        target=target_str,
        source_ip=client_ip,
        detail=f"Scan ID: {scan_id}, Profil: {payload.profile}"
    )

    # 5. Delegasikan pekerjaan ke thread pool background FastAPI
    background_tasks.add_task(execute_scan, scan_id, target_str, profile_data)

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Permintaan pemindaian telah diverifikasi dan masuk antrean."
    }

@app.get("/api/scans", response_model=List[ScanResponse], tags=["Scans"])
def get_all_scans() -> List[Dict[str, Any]]:
    """Mengambil seluruh riwayat pemindaian."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC;").fetchall()
        return [dict(row) for row in rows]

@app.get("/api/scans/{scan_id}", response_model=ScanResponse, tags=["Scans"])
def get_scan_by_id(scan_id: str) -> Dict[str, Any]:
    """Mengecek status proses dan metadata pemindaian tertentu."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?;", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data pemindaian tidak ditemukan.")
        return dict(row)

@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse], tags=["Findings"])
def get_scan_findings(scan_id: str) -> List[Dict[str, Any]]:
    """Mengambil rincian temuan kerentanan dari scan yang sudah selesai."""
    with get_db() as conn:
        scan = conn.execute("SELECT scan_id FROM scans WHERE scan_id = ?;", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data pemindaian tidak ditemukan.")

        rows = conn.execute(
            "SELECT id, template_id, name, severity, matched_at, description FROM findings WHERE scan_id = ? ORDER BY id ASC;",
            (scan_id,)
        ).fetchall()
        return [dict(row) for row in rows]

@app.get("/api/scans/{scan_id}/report", response_model=ReportSummary, tags=["Reports"])
def get_scan_report(scan_id: str) -> Dict[str, Any]:
    """Menyajikan ringkasan agregasi distribusi severity temuan."""
    with get_db() as conn:
        scan = conn.execute(
            "SELECT scan_id, target, status, total_findings FROM scans WHERE scan_id = ?;",
            (scan_id,)
        ).fetchone()
        
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data pemindaian tidak ditemukan.")

        summary_rows = conn.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            WHERE scan_id = ? 
            GROUP BY severity;
        """, (scan_id,)).fetchall()

        breakdown = {row["severity"]: row["count"] for row in summary_rows}

        return {
            "scan_id": scan["scan_id"],
            "target": scan["target"],
            "status": scan["status"],
            "total_findings": scan["total_findings"],
            "severity_breakdown": breakdown
        }

# --- Endpoint API: AI Analysis (Gemini) ---

class AIAnalyzeRequest(BaseModel):
    scan_id: str
    gemini_api_key: str

@app.post("/api/ai/analyze", tags=["AI"])
@limiter.limit("5/minute")
async def ai_analyze_scan(
    payload: AIAnalyzeRequest,
    request: Request,
    _auth: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """Menganalisis temuan scan menggunakan Gemini AI dan memberikan rekomendasi remediasi."""
    import httpx

    scan_id = payload.scan_id
    gemini_key = payload.gemini_api_key.strip()

    if not gemini_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Gemini API Key diperlukan.")

    # Ambil data scan & findings
    with get_db() as conn:
        scan = conn.execute(
            "SELECT scan_id, target, profile, status, total_findings FROM scans WHERE scan_id = ?;",
            (scan_id,)
        ).fetchone()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan ID tidak ditemukan.")

        findings_rows = conn.execute(
            "SELECT template_id, name, severity, matched_at, description FROM findings WHERE scan_id = ? ORDER BY id ASC LIMIT 50;",
            (scan_id,)
        ).fetchall()

    scan_data = dict(scan)
    findings_list = [dict(f) for f in findings_rows]

    # Bangun prompt untuk Gemini
    findings_text = ""
    if findings_list:
        for i, f in enumerate(findings_list, 1):
            findings_text += f"\n{i}. [{f['severity'].upper()}] {f['name']}\n"
            findings_text += f"   Template: {f['template_id']}\n"
            findings_text += f"   Matched At: {f['matched_at']}\n"
            if f['description']:
                findings_text += f"   Deskripsi: {f['description'][:200]}\n"
    else:
        findings_text = "Tidak ada kerentanan terdeteksi pada scan ini."

    prompt = f"""Kamu adalah seorang ahli keamanan siber (penetration tester) senior. Analisis hasil pemindaian Nuclei berikut dan berikan laporan analisis keamanan yang komprehensif dalam Bahasa Indonesia.

**Target:** {scan_data['target']}
**Profil Scan:** {scan_data['profile']}
**Status:** {scan_data['status']}
**Total Temuan:** {scan_data['total_findings']}

**Daftar Temuan Kerentanan:**
{findings_text}

Berikan analisis yang mencakup:
1. **Ringkasan Eksekutif** - Gambaran singkat kondisi keamanan target
2. **Analisis Risiko** - Tingkat risiko keseluruhan (Kritis/Tinggi/Sedang/Rendah) beserta alasan
3. **Detail Temuan Kritis** - Penjelasan mendalam untuk temuan dengan severity tinggi/kritis
4. **Rekomendasi Remediasi** - Langkah-langkah konkret untuk memperbaiki setiap kerentanan utama
5. **Prioritas Tindakan** - Urutan perbaikan yang disarankan berdasarkan dampak bisnis

Format respons menggunakan Markdown yang rapi dan terstruktur."""

    # Panggil Gemini API
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}"
            payload_gemini = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.4,
                    "maxOutputTokens": 4096
                }
            }
            resp = await client.post(gemini_url, json=payload_gemini)
            if resp.status_code != 200:
                error_detail = resp.json().get("error", {}).get("message", "Gemini API error")
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Gemini API Error: {error_detail}")

            gemini_data = resp.json()
            analysis_text = gemini_data["candidates"][0]["content"]["parts"][0]["text"]

    except httpx.TimeoutException:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="Gemini API timeout. Coba lagi.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Gagal menghubungi Gemini: {str(e)}")

    log_audit_event(
        action="ai_analysis",
        target=scan_data["target"],
        source_ip=request.client.host if request.client else "unknown",
        detail=f"AI analisis untuk Scan ID: {scan_id}"
    )

    return {
        "scan_id": scan_id,
        "target": scan_data["target"],
        "analysis": analysis_text,
        "findings_analyzed": len(findings_list),
        "model": "gemini-2.0-flash"
    }


@app.get("/api/stats", tags=["Dashboard"])
def get_dashboard_stats() -> Dict[str, Any]:
    """Statistik ringkasan untuk dashboard overview."""
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) as c FROM scans;").fetchone()["c"]
        completed_scans = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='completed';").fetchone()["c"]
        running_scans = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status IN ('running','queued');").fetchone()["c"]
        failed_scans = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='failed';").fetchone()["c"]
        total_findings = conn.execute("SELECT SUM(total_findings) as s FROM scans WHERE status='completed';").fetchone()["s"] or 0
        critical_findings = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='critical';").fetchone()["c"]
        high_findings = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='high';").fetchone()["c"]
        targets_monitored = conn.execute("SELECT COUNT(*) as c FROM allowlist;").fetchone()["c"]
        recent_scans = conn.execute(
            "SELECT scan_id, target, profile, status, total_findings, started_at FROM scans ORDER BY started_at DESC LIMIT 5;"
        ).fetchall()

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "total_findings": int(total_findings),
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "targets_monitored": targets_monitored,
        "recent_scans": [dict(r) for r in recent_scans]
    }