import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from database import get_db

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def resolve_nuclei_path() -> str:
    """Mendeteksi lokasi binary Nuclei di sistem."""
    path = shutil.which("nuclei")
    if not path:
        home_go_bin = Path.home() / "go" / "bin" / "nuclei"
        if home_go_bin.is_file():
            return str(home_go_bin)
        raise FileNotFoundError("Binary 'nuclei' tidak ditemukan di PATH sistem atau $HOME/go/bin.")
    return path

def resolve_target_for_docker(target: str) -> str:
    """
    Memetakan target localhost ke nama host internal Docker.
    Contoh: http://localhost:3000 -> http://juice-shop:3000
    agar eksekusi pemindaian di dalam kontainer tidak gagal (Connection Refused).
    """
    clean_target = target.strip()
    # Pemetaan untuk target latihan Juice Shop di docker-compose
    if "localhost:3000" in clean_target or "127.0.0.1:3000" in clean_target:
        return clean_target.replace("localhost:3000", "juice-shop:3000").replace("127.0.0.1:3000", "juice-shop:3000")
    return clean_target

def build_cli_command(
    nuclei_bin: str,
    target: str,
    profile_data: Dict[str, Any]
) -> List[str]:
    """Menyusun argumen CLI Nuclei secara optimal, cepat, dan deterministik."""
    # Resolusi target untuk jaringan Docker
    resolved_target = resolve_target_for_docker(target)

    cmd = [
        nuclei_bin,
        "-target", resolved_target,
        "-rate-limit", str(profile_data.get("rate_limit", 50)),
        "-concurrency", str(profile_data.get("concurrency", 10)),
        "-timeout", str(profile_data.get("timeout", 5)),
        "-max-host-error", "30",
        "-retries", "1",
        "-no-interactsh",
        "-silent",
        "-jsonl"
    ]

    if profile_data.get("tags"):
        cmd.extend(["-tags", ",".join(profile_data["tags"])])

    if profile_data.get("severity"):
        cmd.extend(["-severity", ",".join(profile_data["severity"])])

    return cmd

def save_single_finding(scan_id: str, data: Dict[str, Any], line_str: str) -> None:
    """Menyimpan satu temuan secara instan ke database untuk streaming real-time."""
    info = data.get("info", {})
    record = (
        scan_id,
        data.get("template-id", "unknown"),
        info.get("name", "Unnamed Finding"),
        info.get("severity", "info").lower(),
        data.get("matched-at", ""),
        info.get("description", ""),
        line_str
    )
    with get_db() as conn:
        with conn:
            conn.execute("""
            INSERT INTO findings (
                scan_id, template_id, name, severity, matched_at, description, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """, record)
            conn.execute("""
            UPDATE scans 
            SET total_findings = total_findings + 1
            WHERE scan_id = ?;
            """, (scan_id,))

def execute_scan(scan_id: str, target: str, profile_data: Dict[str, Any]) -> None:
    """Fungsi utama eksekutor pemindaian dengan streaming real-time ke database."""
    output_file = RESULTS_DIR / f"{scan_id}.jsonl"

    # Tandai status scan dimulai
    with get_db() as conn:
        with conn:
            conn.execute(
                "UPDATE scans SET status = 'running', started_at = ? WHERE scan_id = ?;",
                (datetime.now(timezone.utc).isoformat(), scan_id)
            )

    total_findings = 0
    process = None

    try:
        nuclei_bin = resolve_nuclei_path()
        command = build_cli_command(nuclei_bin, target, profile_data)

        with open(output_file, "w", encoding="utf-8") as out_f:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            # Stream stdout per baris secara real-time
            if process.stdout:
                for line in process.stdout:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    
                    try:
                        data = json.loads(line_str)
                        out_f.write(line_str + "\n")
                        out_f.flush()
                        
                        save_single_finding(scan_id, data, line_str)
                        total_findings += 1
                    except json.JSONDecodeError:
                        continue

            stderr_output = ""
            if process.stderr:
                stderr_output = process.stderr.read()

            process.wait(timeout=1800)

            if process.returncode != 0 and total_findings == 0:
                error_output = stderr_output.strip() or f"Proses Nuclei berhenti dengan kode {process.returncode}."
                raise RuntimeError(error_output[:500])

        # Perbarui status berhasil
        with get_db() as conn:
            with conn:
                conn.execute("""
                UPDATE scans 
                SET status = 'completed', 
                    total_findings = ?, 
                    finished_at = ? 
                WHERE scan_id = ?;
                """, (total_findings, datetime.now(timezone.utc).isoformat(), scan_id))

    except subprocess.TimeoutExpired:
        if process and process.poll() is None:
            process.kill()
        with get_db() as conn:
            with conn:
                conn.execute(
                    "UPDATE scans SET status = 'failed', error_message = ?, total_findings = ? WHERE scan_id = ?;",
                    ("Pemindaian melebihi batas waktu maksimal (timeout).", total_findings, scan_id)
                )
    except Exception as exc:
        if process and process.poll() is None:
            process.kill()
        with get_db() as conn:
            with conn:
                conn.execute(
                    "UPDATE scans SET status = 'failed', error_message = ?, total_findings = ? WHERE scan_id = ?;",
                    (str(exc)[:500], total_findings, scan_id)
                )