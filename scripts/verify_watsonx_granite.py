#!/usr/bin/env python3
"""Verify live credentials, connectivity, and parsing for Granite on watsonx.ai.

This script always calls the real IBM watsonx.ai API. It does not read
application settings or mock flags.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

MODEL_ID = "ibm/granite-13b-instruct-v2"
DEFAULT_URL = "https://us-south.ml.cloud.ibm.com"
PROMPT = 'System: Respond strictly with JSON: {"status": "ok"}'
PLACEHOLDERS = frozenset(
    {
        "",
        "your_watsonx_api_key_here",
        "your_watsonx_project_id_here",
        "YOUR_WATSONX_API_KEY",
        "YOUR_WATSONX_PROJECT_ID",
    }
)
PARAMETERS = {
    "decoding_method": "greedy",
    "max_new_tokens": 20,
    "min_new_tokens": 1,
}


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    # Existing process environment wins over .env.
    load_dotenv(env_path, override=False)


def _require_credentials() -> tuple[str, str, str]:
    missing: list[str] = []
    api_key = os.environ.get("WATSONX_API_KEY", "").strip()
    project_id = os.environ.get("WATSONX_PROJECT_ID", "").strip()
    url = os.environ.get("WATSONX_URL", "").strip() or DEFAULT_URL

    if api_key in PLACEHOLDERS:
        missing.append("WATSONX_API_KEY")
    if project_id in PLACEHOLDERS:
        missing.append("WATSONX_PROJECT_ID")
    if missing:
        print(
            "ERROR: Missing environment variables (no API request was sent): "
            + ", ".join(missing),
            file=sys.stderr,
        )
        print(
            "Set WATSONX_API_KEY and WATSONX_PROJECT_ID in the environment or in .env. "
            f"WATSONX_URL defaults to {DEFAULT_URL}.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return api_key, project_id, url


def _status_and_body(exc: BaseException) -> tuple[int | None, str]:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    body = getattr(response, "text", None)
    http_status = int(status) if isinstance(status, int) else None
    detail = body if isinstance(body, str) and body.strip() else str(exc)
    return http_status, detail


def _diagnose(status: int | None, body: str) -> str:
    lowered = body.lower()
    if "invalid_instance_status" in lowered or "current status: inactive" in lowered:
        return (
            "ERROR: The watsonx Machine Learning service instance for this project is "
            "inactive. In IBM Cloud, open the watsonx.ai runtime linked to "
            "WATSONX_PROJECT_ID and reactivate it, then rerun this script.\n"
            f"Detail: {body}"
        )
    if status == 401 or any(
        token in lowered
        for token in ("invalid apikey", "invalid api key", "authentication", "unauthorized")
    ):
        return (
            "ERROR: Authentication failed. Confirm WATSONX_API_KEY is a valid IBM Cloud "
            "API key and that WATSONX_URL is the watsonx.ai region that accepts it.\n"
            f"Detail: {body}"
        )
    if status == 404 or any(
        token in lowered
        for token in (
            "model not found",
            "model_not_found",
            "not supported",
            "does not exist",
            "unknown model",
            "model is not available",
        )
    ):
        return (
            f"ERROR: Model {MODEL_ID} is not available for this project or region. "
            "Enable the model in the watsonx project, or point WATSONX_URL at the region "
            "where it is deployed.\n"
            f"Detail: {body}"
        )
    if any(
        token in lowered
        for token in (
            "invalid project",
            "project id",
            "project_id is",
            "project not found",
            "provided project",
        )
    ):
        return (
            "ERROR: The watsonx project was rejected. Confirm WATSONX_PROJECT_ID is the "
            "project GUID for the same IBM Cloud account and region as WATSONX_URL.\n"
            f"Detail: {body}"
        )
    return (
        "ERROR: watsonx.ai request failed. Check WATSONX_API_KEY, WATSONX_PROJECT_ID, "
        f"WATSONX_URL, and that {MODEL_ID} is enabled.\n"
        f"Detail: {body}"
    )


def _generated_text(response: object) -> tuple[str, str]:
    if not isinstance(response, dict):
        raw = str(response)
        return raw, raw
    raw = json.dumps(response, ensure_ascii=False)
    results = response.get("results") or []
    if results and isinstance(results[0], dict):
        return raw, str(results[0].get("generated_text", ""))
    return raw, ""


def main() -> int:
    _load_dotenv()
    # Ignore mock switches so this script cannot be short-circuited.
    for key in ("WATSONX_MOCK", "WATSONX_USE_MOCK", "SIEVE_MOCK", "USE_MOCK"):
        os.environ.pop(key, None)

    api_key, project_id, url = _require_credentials()

    try:
        from ibm_watsonx_ai import Credentials
        from ibm_watsonx_ai.foundation_models import ModelInference
    except ImportError:
        print(
            "ERROR: ibm-watsonx-ai is not installed. "
            "Install it with: python3 -m pip install ibm-watsonx-ai",
            file=sys.stderr,
        )
        return 1

    logging.getLogger("ibm_watsonx_ai").setLevel(logging.CRITICAL)

    model = ModelInference(
        model_id=MODEL_ID,
        credentials=Credentials(url=url, api_key=api_key),
        project_id=project_id,
        params=PARAMETERS,
        validate=False,
    )

    started = time.perf_counter()
    try:
        response = model.generate(prompt=PROMPT)
    except Exception as exc:  # noqa: BLE001 — report any SDK or network failure
        elapsed = time.perf_counter() - started
        status, body = _status_and_body(exc)
        print(f"elapsed_s={elapsed:.3f}", flush=True)
        print(f"http_status={status if status is not None else 'n/a'}", flush=True)
        print(_diagnose(status, body), file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - started
    raw, generated = _generated_text(response)
    print(f"model_id={MODEL_ID}")
    print(f"elapsed_s={elapsed:.3f}")
    print("http_status=200")
    print(f"raw_response={raw}")
    print(f"generated_text={generated}")
    if not generated.strip():
        print(
            "ERROR: The API returned a body with no generated text. Response parsing failed.",
            file=sys.stderr,
        )
        return 1
    print(f"SUCCESS: model {MODEL_ID} is active and reachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
