# ============================================================
# llm/llm_client.py — Ollama LLM Client
# ============================================================
# Calls local Llama model via Ollama.
# Handles:
#   - JSON extraction (Llama sometimes adds extra text)
#   - Retry on parse failure (once)
#   - Fallback values if model fails completely
#
# Docker note:
#   When running via docker compose, OLLAMA_HOST is set to
#   http://ollama:11434 automatically via docker-compose.yml.
#   When running locally, it defaults to http://localhost:11434.
# ============================================================

import json
import os
import re
import ollama
from config import LLM_MODEL


# ── Ollama host: reads from environment, falls back to localhost ──────
# This is the key change that makes it work inside Docker.
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# Create a custom Ollama client pointing to the correct host
_client = ollama.Client(host=OLLAMA_HOST)


def _extract_json(text: str) -> dict:
    """
    Extract JSON from model response.
    4 strategies from simple to most robust.
    """
    text = text.strip()

    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: find { ... } block
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except json.JSONDecodeError:
        pass

    # Strategy 3: fix truncated JSON by closing open braces
    try:
        open_braces = text.count('{') - text.count('}')
        fixed = text + ('}' * open_braces)
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # Strategy 4: regex field extraction — works even on heavily truncated responses
    try:
        result = {}

        # Extract string fields
        for key in ["explanation", "exploit", "patched_code", "cwe"]:
            match = re.search(rf'"{key}"\s*:\s*"([^"]*)"', text)
            if match:
                result[key] = match.group(1)

        # Extract float field separately (not quoted)
        conf_match = re.search(r'"severity_confidence"\s*:\s*([0-9.]+)', text)
        if conf_match:
            result["severity_confidence"] = float(conf_match.group(1))

        # Return if we got at least 4 out of 5 fields
        if len(result) >= 4:
            return result
    except Exception:
        pass

    return None


def call_llm(prompt: str, retries: int = 1) -> dict:
    """
    Call Llama via Ollama and return parsed JSON response.

    Args:
        prompt: The structured prompt string
        retries: How many times to retry on parse failure (default 1)

    Returns:
        Parsed dict from model, or fallback dict on failure
    """
    for attempt in range(retries + 1):
        try:
            response = _client.chat(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,   # low temp = more deterministic JSON
                    "num_predict": 1024,   # enough for our JSON structure
                }
            )

            raw_text = response['message']['content']
            parsed = _extract_json(raw_text)

            if parsed:
                return parsed
            else:
                print(f"  [LLM] JSON parse failed (attempt {attempt + 1}), raw: {raw_text[:100]}")

        except Exception as e:
            print(f"  [LLM] Error on attempt {attempt + 1}: {e}")

    # Fallback — return safe defaults so pipeline doesn't break
    print("  [LLM] Using fallback response after all retries failed")
    return {
        "explanation": "Could not generate explanation",
        "exploit": "Could not generate exploit",
        "patched_code": "# Could not generate patch",
        "cwe": "Unknown",
        "severity_confidence": 0.5
    }


def call_llm_raw(prompt: str) -> str:
    """
    Returns raw text response (used for debugging).
    """
    try:
        response = _client.chat(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1}
        )
        return response['message']['content']
    except Exception as e:
        return f"Error: {e}"