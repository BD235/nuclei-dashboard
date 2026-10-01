import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import redis
from config import CONFIG


def resolve_nuclei_path() -> str:
    """Mendeteksi lokasi binary nuclei pada sistem."""
    path = shutil.which("nuclei")
    if path:
        return path

    custom_paths = [
        Path.home() / "go" / "bin" / "nuclei",
        Path("/usr/local/bin/nuclei"),
        Path("/usr/bin/nuclei"),
    ]
    for p in custom_paths:
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)

    return "nuclei"


def is_valid_url(url_string: str) -> bool:
    """Validasi format URL untuk keamanan."""
    try:
        parsed = urlparse(url_string)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def sanitize_tag(tag: str) -> str:
    """Sanitasi tag hanya mengizinkan alfanumerik, strip, koma, dan underscore."""
    return re.sub(r"[^a-zA-Z0-9_\-,]", "", tag)


def execute_scan(r: redis.Redis, nuclei_bin: str, args: list[str], target_url: str, worker_id: str) -> None:
    """
    Eksekusi Nuclei dengan list argumen aman (mencegah command injection)
    dan streaming stdout baris demi baris sehingga temuan langsung tersimpan di Redis.
    """
    cmd = [nuclei_bin] + args
    waf_detected = False

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Stream stdout baris demi baris secara real-time
        if proc.stdout:
            for line in proc.stdout:
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    item = json.loads(line_str)
                    info = item.get("info", {})
                    finding = {
                        "target": target_url,
                        "templateId": item.get("template-id", "unknown"),
                        "name": info.get("name", "Unnamed Finding"),
                        "severity": str(info.get("severity", "info")).lower(),
                        "matchedAt": item.get("matched-at", target_url),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "workerId": worker_id,
                    }

                    # LPUSH ke antrean channel:findings
                    r.lpush(CONFIG["queues"]["findings"], json.dumps(finding))
                    print(
                        f"[!] FINDING [{finding['severity'].upper()}] -> {finding['target']} ({finding['name']})",
                        flush=True,
                    )
                except json.JSONDecodeError:
                    continue

        stderr_output = ""
        if proc.stderr:
            stderr_output = proc.stderr.read()

        proc.wait(timeout=1800)

        # Deteksi indikasi WAF atau rate-limit dari output Nuclei
        if "429 Too Many Requests" in stderr_output or "blocked" in stderr_output:
            waf_detected = True

    except subprocess.TimeoutExpired:
        print(f"[!] Scan timeout pada {target_url}", flush=True)
        if 'proc' in locals() and proc:
            proc.kill()
    except Exception as exc:
        print(f"[X] Gagal mengeksekusi Nuclei pada {target_url}: {exc}", file=sys.stderr, flush=True)
        if 'proc' in locals() and proc and proc.poll() is None:
            proc.kill()

    # Dynamic Cooling Down jika terindikasi proteksi WAF / 429
    if waf_detected:
        print(
            f"[!] WAF / Rate Limit terdeteksi pada {target_url}. Melakukan cooling down 5 detik...",
            flush=True,
        )
        time.sleep(5)


def main():
    redis_host = os.getenv("REDIS_HOST", CONFIG["redis"]["host"])
    redis_port = int(os.getenv("REDIS_PORT", CONFIG["redis"]["port"]))
    worker_type = os.getenv("WORKER_TYPE", "FAST").upper()

    worker_id = f"worker-{worker_type.lower()}-{os.urandom(3).hex()}"
    nuclei_bin = resolve_nuclei_path()

    print(f"[🚀] {worker_id} aktif ({worker_type} TRACK) dengan parameter defensif.", flush=True)
    print(f"[*] Menghubungkan ke Redis pada {redis_host}:{redis_port}...", flush=True)

    r = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=CONFIG["redis"]["password"],
        decode_responses=True,
    )

    try:
        r.ping()
        print(f"[✓] {worker_id} berhasil terhubung ke Redis.", flush=True)
    except redis.ConnectionError as e:
        print(f"[X] Gagal terhubung ke Redis: {e}", file=sys.stderr)
        sys.exit(1)

    fast_queue = CONFIG["queues"]["fast_track"]
    tech_queue = CONFIG["queues"]["tech_targeted"]
    deep_queue = CONFIG["queues"]["deep_track"]

    while True:
        try:
            if worker_type == "FAST":
                # Prioritas 1: Ambil tugas dari 'queue:tech_targeted' terlebih dahulu
                tech_job = r.rpop(tech_queue)
                if tech_job:
                    try:
                        payload = json.loads(tech_job)
                        url = payload.get("url")
                        tag = payload.get("tag")

                        if url and is_valid_url(url) and tag:
                            safe_tag = sanitize_tag(tag)
                            print(f"[*] {worker_id} memproses TECH TARGETED: {url} (tag: {safe_tag})", flush=True)

                            # Parameter presisi: timeout 8s, rate-limit 60 req/s, toleransi 15 host error
                            args = [
                                "-u", url,
                                "-tags", safe_tag,
                                "-timeout", "8",
                                "-retries", "1",
                                "-max-host-error", "15",
                                "-rl", "60",
                                "-c", "30",
                                "-silent",
                                "-jsonl",
                            ]
                            execute_scan(r, nuclei_bin, args, url, worker_id)
                            continue
                    except json.JSONDecodeError:
                        print(f"[X] Format job tidak valid pada {tech_queue}: {tech_job}", flush=True)

                # Prioritas 2: Ambil tugas dari 'queue:fast_track'
                fast_url = r.rpop(fast_queue)
                if fast_url:
                    if is_valid_url(fast_url):
                        print(f"[*] {worker_id} memproses FAST TRACK: {fast_url}", flush=True)

                        # Parameter fast track: timeout 8s mencakup time-based flaws
                        args = [
                            "-u", fast_url,
                            "-severity", "critical,high",
                            "-timeout", "8",
                            "-retries", "1",
                            "-max-host-error", "15",
                            "-rl", "75",
                            "-c", "40",
                            "-bs", "25",
                            "-silent",
                            "-jsonl",
                        ]
                        execute_scan(r, nuclei_bin, args, fast_url, worker_id)
                        continue

            else:
                # Worker Deep Track: Mengonsumsi tugas dari 'queue:deep_track'
                deep_url = r.rpop(deep_queue)
                if deep_url:
                    if is_valid_url(deep_url):
                        print(f"[*] {worker_id} memproses DEEP TRACK: {deep_url}", flush=True)

                        args = [
                            "-u", deep_url,
                            "-severity", "medium,low",
                            "-tags", "misconfig,exposure",
                            "-timeout", "8",
                            "-retries", "1",
                            "-max-host-error", "15",
                            "-rl", "50",
                            "-c", "25",
                            "-silent",
                            "-jsonl",
                        ]
                        execute_scan(r, nuclei_bin, args, deep_url, worker_id)
                        continue

            # Jika antrean kosong, jeda 2 detik
            time.sleep(2)

        except redis.ConnectionError as e:
            print(f"[X] Koneksi Redis terputus pada {worker_id}: {e}. Mencoba kembali...", flush=True)
            time.sleep(3)
        except KeyboardInterrupt:
            print(f"\n[*] Menghentikan {worker_id} secara anggun...", flush=True)
            break
        except Exception as e:
            print(f"[X] Error pada worker loop {worker_id}: {e}", file=sys.stderr, flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
