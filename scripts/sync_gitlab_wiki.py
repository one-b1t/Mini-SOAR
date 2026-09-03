import json
import os
import re
import subprocess
import sys

PROJECT_ID = "242"

SIDEBAR_CONTENT = """### [⚡ MiniSOAR Wiki](home)

* 📖 **[Home](home)**
* 🧭 **[Overview](Overview)**
* 🏗️ **[Architecture](Architecture)**
* 🧠 **[MLOps Workflow](MLOps)**
* 🗄️ **[Database & Cache](Database)**
* 📡 **[API Reference](API-Reference)**
* 🚀 **[Deployment](Deployment)**
* 🧪 **[Testing Gates](Testing)**
* 🛠️ **[Troubleshooting](Troubleshooting)**
* 📝 **[Changelog](Changelog)**

---
*Repo: [oneb1t/mini-soar](https://rks.komdigi.go.id/oneb1t/mini-soar)*
"""

PAGES_TO_SYNC = [
    {
        "slug": "home",
        "title": "home",
        "file": "WIKI.md",
    },
    {
        "slug": "Overview",
        "title": "Overview",
        "file": "docs/overview.md"
    },
    {
        "slug": "Architecture",
        "title": "Architecture",
        "file": "docs/architecture.md"
    },
    {
        "slug": "MLOps",
        "title": "MLOps",
        "file": "docs/mlops.md"
    },
    {
        "slug": "Database",
        "title": "Database",
        "file": "docs/database.md"
    },
    {
        "slug": "API-Reference",
        "title": "API-Reference",
        "file": "docs/api.md"
    },
    {
        "slug": "Deployment",
        "title": "Deployment",
        "file": "docs/deployment.md"
    },
    {
        "slug": "Testing",
        "title": "Testing",
        "file": "docs/testing.md"
    },
    {
        "slug": "Troubleshooting",
        "title": "Troubleshooting",
        "file": "docs/troubleshooting.md"
    },
    {
        "slug": "Changelog",
        "title": "Changelog",
        "file": "Changelog.md"
    },
    {
        "slug": "_sidebar",
        "title": "_sidebar",
        "raw_content": SIDEBAR_CONTENT
    }
]

def run_glab_api(endpoint, method="GET", data=None):
    cmd = ["glab", "api"]
    if method != "GET":
        cmd.extend(["-X", method])
    cmd.append(endpoint)
    
    if data:
        for k, v in data.items():
            cmd.extend(["-F", f"{k}={v}"])
            
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        return {"error": res.stderr.strip()}
    try:
        return json.loads(res.stdout)
    except Exception:
        return {"raw": res.stdout.strip()}

def get_existing_wiki_slugs():
    data = run_glab_api(f"projects/{PROJECT_ID}/wikis")
    if isinstance(data, list):
        return {p["slug"] for p in data}
    return set()

def cleanup_old_slugs(existing_slugs, valid_slugs):
    for slug in existing_slugs:
        if slug not in valid_slugs:
            print(f"[*] Menghapus slug lama: {slug}")
            run_glab_api(f"projects/{PROJECT_ID}/wikis/{slug}", method="DELETE")

def adjust_links_for_wiki(content):
    link_map = {
        r"docs/overview\.md": "Overview",
        r"docs/architecture\.md": "Architecture",
        r"docs/mlops\.md": "MLOps",
        r"docs/database\.md": "Database",
        r"docs/api\.md": "API-Reference",
        r"docs/deployment\.md": "Deployment",
        r"docs/testing\.md": "Testing",
        r"docs/troubleshooting\.md": "Troubleshooting",
        r"Readme\.md": "home",
        r"WIKI\.md": "home",
        r"Changelog\.md": "Changelog",
    }
    adjusted = content
    for pattern, wiki_slug in link_map.items():
        adjusted = re.sub(rf"\[([^\]]+)\]\((?:file:///[^)]*|(?:\./)?)?{pattern}(?:#[^)]*)?\)", rf"[\1]({wiki_slug})", adjusted)
    return adjusted

def build_home_content():
    wiki_header = """# ⚡ MiniSOAR Official Documentation & Wiki

Selamat datang di **Wiki Resmi MiniSOAR** (*Security Orchestration, Automation, and Response*).

---

## 📚 Daftar Navigasi Dokumentasi (Table of Contents)

| Halaman Wiki | Deskripsi Dokumen |
| :--- | :--- |
| 📖 **[System Overview](Overview)** | Peta kapabilitas 5-Tier, arsitektur modular, dan integrasi enterprise. |
| 🏗️ **[System Architecture](Architecture)** | Aliran siklus hidup event, diagram pipeline, korelasi log, dan orkestrasi playbook. |
| 🧠 **[MLOps & Auto-Retraining](MLOps)** | Alur 7-Step ML lifecycle, evaluasi threshold, pencegahan bias data, dan SecureSphere attack replay. |
| 🗄️ **[Database & Cache](Database)** | Skema indeks Elasticsearch cluster, struktur key Redis, dan TTL audit log. |
| 📡 **[API & Command Reference](API-Reference)** | Referensi lengkap command interaktif Telegram Bot dan CLI `minisoar.sh`. |
| 🚀 **[Production Deployment](Deployment)** | Panduan deployment bare-metal/systemd/container, hardening keamanan, dan rotasi credential. |
| 🧪 **[Testing & Quality Gates](Testing)** | Strategi pengujian unit/integrasi (Pytest), cakupan pengujian, dan CI gates. |
| 🛠️ **[Troubleshooting Runbook](Troubleshooting)** | Prosedur diagnostik insiden umum, pemulihan antrean Redis, dan recovery model ML. |
| 📝 **[Changelog](Changelog)** | Riwayat rilis versi, fitur baru, refactoring, dan perbaikan keamanan. |

---

"""
    with open("WIKI.md", "r", encoding="utf-8") as f:
        wiki_md = f.read()

    with open("Readme.md", "r", encoding="utf-8") as f:
        readme_md = f.read()

    combined = wiki_header + "\n\n" + wiki_md + "\n\n---\n\n## 📄 Ringkasan Teknis (Readme)\n\n" + readme_md
    return adjust_links_for_wiki(combined)

def sync():
    valid_slugs = {item["slug"] for item in PAGES_TO_SYNC}
    existing_slugs = get_existing_wiki_slugs()
    print(f"[*] Halaman Wiki saat ini di GitLab: {existing_slugs}")

    cleanup_old_slugs(existing_slugs, valid_slugs)

    # Siapkan juga direktori export lokal untuk GitHub Wiki
    github_wiki_dir = "docs/github-wiki"
    os.makedirs(github_wiki_dir, exist_ok=True)

    # Simpan sidebar untuk GitHub
    with open(os.path.join(github_wiki_dir, "_Sidebar.md"), "w", encoding="utf-8") as sb_f:
        sb_f.write(SIDEBAR_CONTENT)

    existing_slugs_after_clean = get_existing_wiki_slugs()

    for item in PAGES_TO_SYNC:
        slug = item["slug"]
        title = item["title"]

        if slug == "home":
            content = build_home_content()
        elif "raw_content" in item:
            content = item["raw_content"]
        else:
            filepath = item["file"]
            if not os.path.exists(filepath):
                print(f"[!] File tidak ditemukan: {filepath}, lewati.")
                continue
            with open(filepath, "r", encoding="utf-8") as f:
                raw_content = f.read()
            content = adjust_links_for_wiki(raw_content)

        # Simpan salinan lokal untuk GitHub Wiki
        gh_filename = "Home.md" if slug == "home" else f"{slug}.md"
        with open(os.path.join(github_wiki_dir, gh_filename), "w", encoding="utf-8") as gh_f:
            gh_f.write(content)

        # Upload ke GitLab via REST API
        print(f"[*] Sinkronisasi halaman GitLab Wiki: '{slug}'...")
        payload = {
            "title": title,
            "content": content,
            "format": "markdown"
        }

        if slug in existing_slugs_after_clean:
            res = run_glab_api(f"projects/{PROJECT_ID}/wikis/{slug}", method="PUT", data=payload)
        else:
            res = run_glab_api(f"projects/{PROJECT_ID}/wikis", method="POST", data=payload)

        if "error" in res:
            print(f"[ERROR] Gagal sinkronisasi '{slug}': {res['error']}")
        else:
            print(f"[OK] Halaman '{slug}' sukses disinkronkan di GitLab Wiki!")

    print("\n[SUCCESS] Seluruh dokumentasi berhasil diunggah ke GitLab Wiki!")
    print(f"[INFO] Berkas salinan GitHub Wiki tersimpan di '{github_wiki_dir}'.")

if __name__ == "__main__":
    sync()
