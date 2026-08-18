from __future__ import annotations

"""MiniSOAR AI SOC Copilot Engine.

Multi-Provider Router supporting:
1. Google Antigravity / Gemini SDK (google-genai / google.generativeai)
2. Anthropic Claude SDK (anthropic)
3. OpenAI / Codex SDK (openai)
4. Local Ollama Air-Gapped API (requests to local endpoint)
5. Offline Mock fallback

AUTHENTICATION FLEXIBILITY:
- Direct Environment Variables (GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY)
- User-Saved Auth Files (JSON or raw key) via AI_AUTH_FILE, GOOGLE_APPLICATION_CREDENTIALS,
  CLAUDE_AUTH_FILE, OPENAI_AUTH_FILE, or standard user ~/.config paths.
"""

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import requests

logger = logging.getLogger(__name__)


def _get_provider() -> str:
    prov = os.getenv("AI_PROVIDER", "gemini").lower().strip()
    if prov in {"google", "gemini", "antigravity"}:
        return "gemini"
    if prov in {"anthropic", "claude"}:
        return "claude"
    if prov in {"openai", "codex", "gpt"}:
        return "openai"
    if prov in {"ollama", "local"}:
        return "ollama"
    return "gemini"


def _read_file_token(filepath: str | Path) -> str | None:
    """Safely extracts an API key or token from a user auth file (JSON or raw text)."""
    try:
        path = Path(filepath).expanduser().resolve()
        if not path.exists() or not path.is_file():
            return None

        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return None

        # Try parsing as JSON first
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # Common JSON key names used by various SDKs/tools
                for k in ["api_key", "apiKey", "token", "auth_token", "key", "access_token", "secret_key"]:
                    if data.get(k) and isinstance(data[k], str):
                        return data[k].strip()
        except (json.JSONDecodeError, ValueError):
            logger.debug("Auth file %s is not in JSON format, treating as raw string.", filepath)

        # Fallback to plain text string token
        return content.strip()
    except Exception as e:
        logger.debug("Failed to read auth file %s: %s", filepath, e)
        return None


def resolve_auth_credential(provider: str | None = None) -> tuple[str, str | None]:
    """Resolves API Key / Token and returns (token, auth_source_description).

    Checks both environment variables and user-stored auth files.
    """
    prov = (provider or _get_provider()).lower().strip()

    # 1. Google / Gemini / Antigravity
    if prov == "gemini":
        # Env vars
        env_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("ANTIGRAVITY_API_KEY")
        if env_key:
            return env_key.strip(), "env:GEMINI_API_KEY"

        # Explicit Auth Files
        file_candidates = [
            os.getenv("GEMINI_AUTH_FILE"),
            os.getenv("ANTIGRAVITY_AUTH_FILE"),
            os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
            os.getenv("AI_AUTH_FILE"),
            os.getenv("AI_CREDENTIALS_FILE"),
            Path.home() / ".gemini" / "credentials.json",
            Path.home() / ".gemini" / "api_key",
            Path.home() / ".config" / "gcloud" / "application_default_credentials.json",
        ]
        for f in file_candidates:
            if f:
                tok = _read_file_token(f)
                if tok:
                    return tok, f"file:{f}"

    # 2. Anthropic / Claude
    elif prov == "claude":
        env_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
        if env_key:
            return env_key.strip(), "env:ANTHROPIC_API_KEY"

        file_candidates = [
            os.getenv("CLAUDE_AUTH_FILE"),
            os.getenv("ANTHROPIC_AUTH_FILE"),
            os.getenv("AI_AUTH_FILE"),
            os.getenv("AI_CREDENTIALS_FILE"),
            Path.home() / ".anthropic" / "config.json",
            Path.home() / ".claude" / "credentials.json",
            Path.home() / ".claude" / "api_key",
        ]
        for f in file_candidates:
            if f:
                tok = _read_file_token(f)
                if tok:
                    return tok, f"file:{f}"

    # 3. OpenAI / Codex
    elif prov == "openai":
        env_key = os.getenv("OPENAI_API_KEY") or os.getenv("CODEX_API_KEY")
        if env_key:
            return env_key.strip(), "env:OPENAI_API_KEY"

        file_candidates = [
            os.getenv("OPENAI_AUTH_FILE"),
            os.getenv("CODEX_AUTH_FILE"),
            os.getenv("AI_AUTH_FILE"),
            os.getenv("AI_CREDENTIALS_FILE"),
            Path.home() / ".openai" / "api_key",
            Path.home() / ".config" / "openai" / "credentials.json",
        ]
        for f in file_candidates:
            if f:
                tok = _read_file_token(f)
                if tok:
                    return tok, f"file:{f}"

    return "", None


def _get_api_key() -> str:
    token, _ = resolve_auth_credential(_get_provider())
    return token


def is_configured() -> bool:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return True
    prov = _get_provider()
    if prov == "ollama":
        return True
    return bool(_get_api_key())


def get_auth_info() -> dict[str, Any]:
    """Returns metadata about the active AI configuration and auth method."""
    prov = _get_provider()
    token, source = resolve_auth_credential(prov)
    model = os.getenv("AI_MODEL", "default")
    is_mock = os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}

    return {
        "provider": prov,
        "model": model,
        "is_mock": is_mock,
        "configured": is_mock or (prov == "ollama") or bool(token),
        "auth_source": source or ("mock" if is_mock else "none"),
        "key_masked": f"{token[:6]}...{token[-4:]}" if len(token) > 10 else ("***" if token else None),
    }


def set_active_model(model_name: str) -> str:
    """Dynamically sets the active AI model in runtime without modifying source code."""
    model = model_name.strip()
    os.environ["AI_MODEL"] = model
    return model


def set_active_provider(provider_name: str) -> str:
    """Dynamically switches the active AI provider in runtime."""
    prov = provider_name.strip().lower()
    os.environ["AI_PROVIDER"] = prov
    return _get_provider()



# ---------------------------------------------------------
# Provider Dispatchers
# ---------------------------------------------------------

def _call_gemini(prompt: str, system_instruction: str = "") -> str:
    """Calls Google Gemini API using google.generativeai or REST API."""
    api_key, auth_source = resolve_auth_credential("gemini")
    model_name = os.getenv("AI_MODEL", "gemini-1.5-flash")

    # If user provided a Google Service Account JSON file path
    service_account_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GEMINI_AUTH_FILE")

    try:
        import google.generativeai as genai

        if api_key:
            genai.configure(api_key=api_key)
        elif service_account_file and Path(service_account_file).exists():
            # Support service account credentials via google.auth if google-auth installed
            try:
                from google.oauth2 import service_account
                creds = service_account.Credentials.from_service_account_file(service_account_file)
                genai.configure(credentials=creds)
            except Exception as e_sa:
                logger.debug("Failed to load service account: %s", e_sa)

        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=system_instruction if system_instruction else None,
        )
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.debug("google.generativeai SDK call failed, falling back to REST: %s", e)
        if not api_key:
            raise RuntimeError(f"Gemini API key not found in environment or auth file: {e}")

        # Fallback to direct REST call
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system_instruction}\n\n{prompt}".strip()}]}]
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 200:
            candidates = resp.json().get("candidates", [])
            if candidates:
                return candidates[0]["content"]["parts"][0]["text"].strip()
        raise RuntimeError(f"Gemini API error: HTTP {resp.status_code} {resp.text[:200]}")


def _call_claude(prompt: str, system_instruction: str = "") -> str:
    """Calls Anthropic Claude API using anthropic SDK or REST."""
    api_key, auth_source = resolve_auth_credential("claude")
    model_name = os.getenv("AI_MODEL", "claude-3-5-sonnet-20241022")

    if not api_key:
        raise RuntimeError("Claude API key/token not found in environment (ANTHROPIC_API_KEY) or auth file (CLAUDE_AUTH_FILE).")

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model_name,
            max_tokens=2048,
            system=system_instruction or "You are an expert SOC Analyst Copilot for MiniSOAR.",
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()
    except Exception as e:
        logger.debug("anthropic SDK call failed, falling back to REST: %s", e)
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model_name,
            "max_tokens": 2048,
            "system": system_instruction or "You are an expert SOC Analyst Copilot for MiniSOAR.",
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()["content"][0]["text"].strip()
        raise RuntimeError(f"Claude API error: HTTP {resp.status_code} {resp.text[:200]}")


def _call_openai(prompt: str, system_instruction: str = "") -> str:
    """Calls OpenAI / Codex API using openai SDK or REST."""
    api_key, auth_source = resolve_auth_credential("openai")
    model_name = os.getenv("AI_MODEL", "gpt-4o")

    if not api_key:
        raise RuntimeError("OpenAI API key not found in environment (OPENAI_API_KEY) or auth file (OPENAI_AUTH_FILE).")

    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_instruction or "You are an expert SOC Analyst Copilot for MiniSOAR."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.debug("openai SDK call failed, falling back to REST: %s", e)
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_instruction or "You are an expert SOC Analyst Copilot for MiniSOAR."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        raise RuntimeError(f"OpenAI API error: HTTP {resp.status_code} {resp.text[:200]}")


def _call_ollama(prompt: str, system_instruction: str = "") -> str:
    """Calls Local Ollama instance (air-gapped SOC)."""
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model_name = os.getenv("AI_MODEL", "llama3")

    url = f"{base_url}/api/generate"
    payload = {
        "model": model_name,
        "system": system_instruction,
        "prompt": prompt,
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=45)
    if resp.status_code == 200:
        return resp.json().get("response", "").strip()
    raise RuntimeError(f"Ollama API error: HTTP {resp.status_code}")


def _get_exec_mode() -> str:
    return os.getenv("AI_EXECMODE", "auto").lower().strip()


def _call_headless_cli(provider: str, prompt: str, system_instruction: str = "") -> str | None:
    """Executes Headless CLI for Google Antigravity, Anthropic Claude, or OpenAI Codex.

    CLI Headless Specifications:
    - Google Antigravity CLI (`antigravity run --headless --json` / `agy exec --json`)
    - Anthropic Claude Code CLI (`claude -p --output-format json`)
    - OpenAI Codex CLI (`codex exec --format json`)
    """
    combined_prompt = f"{system_instruction}\n\n{prompt}".strip() if system_instruction else prompt
    model_name = os.getenv("AI_MODEL", "")

    # 1. Antigravity / Gemini CLI Headless Mode
    if provider == "gemini":
        cli_bin = (
            os.getenv("ANTIGRAVITY_CLI_PATH")
            or os.getenv("AGY_CLI_PATH")
            or shutil.which("antigravity")
            or shutil.which("agy")
        )
        if not cli_bin:
            return None
        cmd = [cli_bin, "run", "--headless", "--json", combined_prompt]
        if model_name:
            cmd.extend(["--model", model_name])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            logger.debug("Antigravity Headless CLI returned code %s: %s", res.returncode, res.stderr)
        except Exception as e:
            logger.debug("Antigravity Headless CLI execution error: %s", e)
        return None

    # 2. Anthropic Claude Code CLI Headless Mode
    if provider == "claude":
        cli_bin = os.getenv("CLAUDE_CLI_PATH") or shutil.which("claude")
        if not cli_bin:
            return None
        cmd = [cli_bin, "-p", "--output-format", "json", combined_prompt]
        if model_name:
            cmd.extend(["--model", model_name])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            logger.debug("Claude Headless CLI returned code %s: %s", res.returncode, res.stderr)
        except Exception as e:
            logger.debug("Claude Headless CLI execution error: %s", e)
        return None

    # 3. OpenAI / Codex CLI Headless Mode
    if provider == "openai":
        cli_bin = os.getenv("CODEX_CLI_PATH") or shutil.which("codex")
        if not cli_bin:
            return None
        cmd = [cli_bin, "exec", "--format", "json", combined_prompt]
        if model_name:
            cmd.extend(["--model", model_name])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            logger.debug("Codex Headless CLI returned code %s: %s", res.returncode, res.stderr)
        except Exception as e:
            logger.debug("Codex Headless CLI execution error: %s", e)
        return None

    return None


def call_llm(prompt: str, system_instruction: str = "") -> str:
    """Dispatches prompt to configured AI LLM provider with Headless CLI & SDK fallbacks."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return (
            "🤖 **[AI SOC Copilot - Mock Analysis]**\n\n"
            "• **Threat Classification:** High Severity Web Attack / Remote Code Execution (RCE)\n"
            "• **MITRE ATT&CK:** `T1059.004` (Command and Scripting Interpreter: Unix Shell), `T1190` (Exploit Public-Facing Application)\n"
            "• **Attack Mechanism:** Penyerang mencoba mengunggah payload terselubung dan mengeksekusi perintah sistem.\n"
            "• **Rekomendasi Respon:**\n"
            "  1. Segera blokir IP sumber pada perimeter WAF (Imperva/Cloudflare/Palo Alto).\n"
            "  2. Isolasi endpoint terdampak pada EDR (Kaspersky KSC / TrendMicro Vision One).\n"
            "  3. Periksa direktori `/uploads` pada web server dan lakukan review integritas berkas."
        )

    provider = _get_provider()
    exec_mode = _get_exec_mode()

    # Try Headless CLI execution if mode is headless, cli, or auto
    if exec_mode in {"headless", "auto", "cli"}:
        cli_output = _call_headless_cli(provider, prompt, system_instruction)
        if cli_output:
            return cli_output
        if exec_mode == "headless":
            raise RuntimeError(f"Headless CLI execution failed for provider '{provider}'. Ensure CLI binary is on PATH.")

    # Fallback to SDK or REST API
    try:
        if provider == "gemini":
            return _call_gemini(prompt, system_instruction)
        if provider == "claude":
            return _call_claude(prompt, system_instruction)
        if provider == "openai":
            return _call_openai(prompt, system_instruction)
        if provider == "ollama":
            return _call_ollama(prompt, system_instruction)
    except Exception as e:
        logger.error("AI Copilot call failed (%s): %s", provider, e)
        return f"⚠️ AI Copilot error ({provider}): {e}"

    return "⚠️ AI Provider not recognized."


# ---------------------------------------------------------
# Core SOC Copilot Capabilities
# ---------------------------------------------------------

SYSTEM_SOC_INSTRUCTION = """Anda adalah Senior SOC Analyst dan Security Copilot untuk platform MiniSOAR.
Tugas Anda:
1. Menganalisis payload serangan, deobfuskasi (Base64, Hex, URL encoding, PowerShell, PHP), dan jelaskan risikonya secara teknis namun ringkas.
2. Memetakan teknik ke taktik MITRE ATT&CK (ID & Nama).
3. Memberikan Root Cause Analysis (RCA) dan rekomendasi mitigasi taktis/strategis.
4. Jawab dalam Bahasa Indonesia profesional yang lugas untuk analis SOC."""


def analyze_payload(payload_str: str) -> str:
    """Deobfuscates and analyzes a suspicious request payload or script."""
    prompt = f"""Harap analisis payload keamanan berikut:
```
{payload_str[:4000]}
```

Format respon:
1. 🔍 **Deobfuskasi & Penjelasan Payload:** (Apa yang coba dieksekusi penyerang?)
2. 🎯 **Taktik & Teknik MITRE ATT&CK:**
3. ⚡ **Tingkat Keparahan & Dampak Potensial:**
4. 🛡️ **Rekomendasi Tindakan Cepat (Containment):**"""

    return call_llm(prompt, SYSTEM_SOC_INSTRUCTION)


def generate_rca(event_id_or_ip: str, logs: list[dict[str, Any]] | None = None) -> str:
    """Generates Root Cause Analysis (RCA) for an incident based on aggregated logs."""
    logs_summary = json.dumps(logs[:15], indent=2) if logs else f"Target Asset / Attacker IP: {event_id_or_ip}"
    prompt = f"""Buatkan Root Cause Analysis (RCA) komprehensif untuk insiden berikut:
Target/IP: {event_id_or_ip}

Log Ringkasan Terkait:
```json
{logs_summary[:3500]}
```

Format laporan RCA:
- 📌 **Executive Summary**
- 🔎 **Vulnerability / Attack Vector yang Digunakan**
- ⏱️ **Timeline & Tahapan Serangan (Kill-Chain)**
- 💥 **Dampak pada Aset**
- 🛠️ **Rekomendasi Perbaikan Jangka Panjang (Remediation)**"""

    return call_llm(prompt, SYSTEM_SOC_INSTRUCTION)


def recommend_mitigation(event_context: dict[str, Any]) -> str:
    """Generates specific perimeter, WAF, and EDR containment rules for an alert."""
    context_str = json.dumps(event_context, indent=2)
    prompt = f"""Berdasarkan konteks alert insiden keamanan berikut:
```json
{context_str[:3000]}
```

Berikan rekomendasi aturan mitigasi teknis konkret:
1. Rule Regex / WAF Policy tuning
2. Konfigurasi Firewall & Perimeter Block
3. Tindakan Endpoint EDR (Kaspersky / TrendMicro)
4. IoC yang harus didistribusikan ke Threat Intel"""

    return call_llm(prompt, SYSTEM_SOC_INSTRUCTION)


def ask_copilot(question: str, context: str = "") -> str:
    """Interactive Q&A for SOC analysts asking about threats, tools, or procedures."""
    prompt = f"""Pertanyaan Analis SOC: {question}

Konteks Tambahan:
{context[:2000] if context else 'Tidak ada konteks tambahan.'}"""

    return call_llm(prompt, SYSTEM_SOC_INSTRUCTION)


# ---------------------------------------------------------
# Structured JSON Output & Headless CLI Capabilities
# ---------------------------------------------------------

def _safe_parse_json(text: str) -> dict[str, Any]:
    """Safely extracts JSON dictionary from raw response string or markdown codeblocks."""
    if not text:
        return {"status": "error", "error": "Empty response"}

    s = text.strip()
    if "```" in s:
        lines = s.splitlines()
        json_lines = []
        inside = False
        for line in lines:
            if line.strip().startswith("```"):
                inside = not inside
                continue
            if inside:
                json_lines.append(line)
        if json_lines:
            s = "\n".join(json_lines).strip()

    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return parsed
        return {"status": "success", "data": parsed}
    except Exception:
        return {
            "status": "raw_text",
            "content": text.strip(),
        }


def call_llm_json(prompt: str, system_instruction: str = "") -> dict[str, Any]:
    """Calls LLM (Headless CLI, SDK, or REST) with strict JSON response formatting."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return {
            "status": "success",
            "provider": _get_provider(),
            "model": os.getenv("AI_MODEL", "mock"),
            "exec_mode": _get_exec_mode(),
            "threat_classification": "High Severity Web Attack / Remote Code Execution (RCE)",
            "severity": "HIGH",
            "mitre_attack": ["T1059.004", "T1190"],
            "summary": "Penyerang mencoba mengunggah payload terselubung dan mengeksekusi perintah sistem.",
            "recommendations": [
                "Blokir IP sumber pada WAF (Imperva/Cloudflare/Palo Alto).",
                "Isolasi endpoint terdampak pada EDR (Kaspersky KSC / TrendMicro).",
                "Review direktori uploads web server."
            ]
        }

    json_instruction = (
        (system_instruction or SYSTEM_SOC_INSTRUCTION)
        + "\n\nCRITICAL MANDATE: Anda HARUS SELALU menjawab HANYA dalam format JSON valid (RFC 8259) tanpa ada kata-kata atau penjelasan di luar objek JSON."
    )
    res_str = call_llm(prompt, json_instruction)
    return _safe_parse_json(res_str)


def analyze_payload_json(payload_str: str) -> dict[str, Any]:
    """Deobfuscates and analyzes a payload, returning a structured JSON object."""
    prompt = f"""Analisis payload keamanan berikut dan kembalikan HANYA JSON valid dengan struktur:
{{
  "threat_classification": "...",
  "severity": "HIGH|MEDIUM|LOW",
  "mitre_attack": ["T1059.004", "T1190"],
  "deobfuscated_payload": "...",
  "explanation": "...",
  "recommendations": ["..."]
}}

Payload:
```
{payload_str[:4000]}
```"""
    return call_llm_json(prompt)


def generate_rca_json(event_id_or_ip: str, logs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Generates structured Root Cause Analysis (RCA) in JSON format."""
    logs_summary = json.dumps(logs[:15], indent=2) if logs else f"Target Asset / Attacker IP: {event_id_or_ip}"
    prompt = f"""Buatkan Root Cause Analysis (RCA) dalam format JSON valid dengan struktur:
{{
  "event_target": "{event_id_or_ip}",
  "executive_summary": "...",
  "attack_vector": "...",
  "timeline": ["..."],
  "impact": "...",
  "remediation": ["..."]
}}

Log Terkait:
```json
{logs_summary[:3500]}
```"""
    return call_llm_json(prompt)

