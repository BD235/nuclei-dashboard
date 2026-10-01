import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
import redis
from config import CONFIG


def resolve_httpx_path() -> str:
    """Mendeteksi lokasi binary httpx pada sistem."""
    path = shutil.which("httpx")
    if path:
        return path

    custom_paths = [
        Path.home() / "go" / "bin" / "httpx",
        Path("/usr/local/bin/httpx"),
        Path("/usr/bin/httpx"),
    ]
    for p in custom_paths:
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)

    return "httpx"


def is_valid_url(url_string: str) -> bool:
    """Validasi format URL untuk keamanan dan mencegah anomali."""
    try:
        parsed = urlparse(url_string)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def main():
    target_file = sys.argv[1] if len(sys.argv) > 1 else "targets.txt"
    target_path = Path(target_file)

    if not target_path.is_file():
        print(f"[!] File target tidak ditemukan: {target_file}", file=sys.stderr)
        sys.exit(1)

    if target_path.stat().st_size == 0:
        print(f"[!] File target kosong: {target_file}", file=sys.stderr)
        sys.exit(1)

    httpx_bin = resolve_httpx_path()
    print(f"[*] Menggunakan binary httpx : {httpx_bin}")
    print(f"[*] Memulai validasi & triase: {target_file}")

    # Inisialisasi koneksi Redis
    r = redis.Redis(
        host=CONFIG["redis"]["host"],
        port=CONFIG["redis"]["port"],
        password=CONFIG["redis"]["password"],
        decode_responses=True,
    )

    try:
        r.ping()
        print(f"[*] Terhubung ke Redis pada {CONFIG['redis']['host']}:{CONFIG['redis']['port']}")
    except redis.ConnectionError as e:
        print(f"[X] Gagal terhubung ke Redis: {e}", file=sys.stderr)
        sys.exit(1)

    # Argumen httpx:
    # Status code luas mencakup 401, 403, 404, 500, 503 untuk menyelamatkan host non-root & internal API
    httpx_args = [
        httpx_bin,
        "-l", str(target_path),
        "-silent",
        "-mc", "200,201,204,301,302,307,308,400,401,403,404,405,500,502,503",
        "-threads", "60",
        "-timeout", "6",
        "-retries", "2",
        "-tech-detect",
        "-json",
    ]

    try:
        proc = subprocess.Popen(
            httpx_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(f"[X] Binary '{httpx_bin}' tidak ditemukan di PATH.", file=sys.stderr)
        sys.exit(1)

    total_live = 0
    total_tech_jobs = 0
    seen_urls = set()

    fast_queue = CONFIG["queues"]["fast_track"]
    tech_queue = CONFIG["queues"]["tech_targeted"]
    deep_queue = CONFIG["queues"]["deep_track"]
    tech_map = CONFIG["tech_tag_map"]

    print("[*] Menunggu streaming hasil dari httpx...")

    if proc.stdout:
        for line in proc.stdout:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
                url = data.get("url")
                if not url or not is_valid_url(url):
                    continue

                if url in seen_urls:
                    continue
                seen_urls.add(url)
                total_live += 1

                # 1. FAST TRACK WAJIB: Seluruh host hidup diuji Critical/High umum
                r.lpush(fast_queue, url)

                # 2. DEEP TRACK: Masuk ke antrean audit mendalam
                r.lpush(deep_queue, url)

                # 3. TECH TARGETED: Tambahan pengujian spesifik jika fingerprint teknologi cocok
                detected_tech = data.get("tech") or []
                if isinstance(detected_tech, list) and detected_tech:
                    for tech_entry in detected_tech:
                        tech_lower = str(tech_entry).lower()
                        for mapping in tech_map:
                            if mapping["match"].lower() in tech_lower:
                                payload = json.dumps({"url": url, "tag": mapping["tag"]})
                                r.lpush(tech_queue, payload)
                                total_tech_jobs += 1

                status_code = data.get("status-code") or data.get("status_code", "HTTP")
                tech_display = ", ".join(detected_tech) if detected_tech else "Generic"
                print(f"[+] Enqueued: [{status_code}] {url} | Tech: {tech_display}")

            except json.JSONDecodeError:
                continue

    proc.wait()
    print(f"\n[✔] Triase Selesai.")
    print(f"    - Total Target Valid Diantrekan : {total_live}")
    print(f"    - Total Tech Targeted Tasks      : {total_tech_jobs}")


if __name__ == "__main__":
    main()
