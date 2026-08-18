from __future__ import annotations

"""MiniSOAR AI SOC Copilot Engine.

Multi-Provider Router supporting:
1. Google Antigravity / Gemini SDK (google-genai / google.generativeai)
2. Anthropic Claude SDK (anthropic)
3. OpenAI / Codex SDK (openai)
4. Local Ollama Air-Gapped API (requests to local endpoint)
5. Offline Mock fallback
"""

import json
import logging
import os
import re
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


def _get_api_key() -> str:
    prov = _get_provider()
    if prov == "gemini":
        return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("ANTIGRAVITY_API_KEY", "")
    if prov == "claude":
        return os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY", "")
    if prov == "openai":
        return os.getenv("OPENAI_API_KEY") or os.getenv("CODEX_API_KEY", "")
    return ""


def is_configured() -> bool:
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return True
    prov = _get_provider()
    if prov == "ollama":
        return True
    return bool(_get_api_key())


# ---------------------------------------------------------
# Provider Dispatchers
# ---------------------------------------------------------

def _call_gemini(prompt: str, system_instruction: str = "") -> str:
    """Calls Google Gemini API using google.generativeai or REST API."""
    api_key = _get_api_key()
    model_name = os.getenv("AI_MODEL", "gemini-1.5-flash")

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=system_instruction if system_instruction else None,
        )
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.debug("google.generativeai SDK call failed, falling back to REST: %s", e)
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
    api_key = _get_api_key()
    model_name = os.getenv("AI_MODEL", "claude-3-5-sonnet-20241022")

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
    api_key = _get_api_key()
    model_name = os.getenv("AI_MODEL", "gpt-4o")

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


def call_llm(prompt: str, system_instruction: str = "") -> str:
    """Dispatches prompt to configured AI LLM provider with graceful fallbacks."""
    if os.getenv("MINISOAR_MOCK", "").lower() in {"1", "true", "yes"}:
        return (
            "🤖 **[AI SOC Copilot - Mock Analysis]**\n\n"
            "• **Threat Classification:** High Severity Web Attack / Remote Code Execution (RCE)\n"
            "• **MITRE ATT&CK:** `T1059.004` (Command and Scripting Interpreter: Unix Shell), `T1190` (Exploit Public-Facing Application)\n"
            "• **Attack Mechanism:** Penyerang mencoba mengunggah webshell terselubung dan mengeksekusi perintah sistem.\n"
            "• **Rekomendasi Respon:**\n"
            "  1. Segera blokir IP sumber pada perimeter WAF (Imperva/Cloudflare/Palo Alto).\n"
            "  2. Isolasi endpoint terdampak pada EDR (Kaspersky KSC / TrendMicro Vision One).\n"
            "  3. Periksa direktori `/uploads` pada web server dan lakukan review integritas berkas."
        )

    provider = _get_provider()
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
