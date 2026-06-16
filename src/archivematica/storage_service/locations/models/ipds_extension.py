"""IPDS signature-extension helpers.

This module provides all the logic required to extend the digital signatures
of documents stored in an Archivematica AIP as part of an IPDS re-preservation
workflow.  It is intentionally free of Archivematica-specific DB/ORM imports
so it can be used both from MCPClient scripts and (via a thin adapter) from
the Storage Service.

Public entry point
------------------
``extend_aip_objects(objects_dir, ipds_doc_name, ipds_doc_id, logger=None)``

    Extend the signatures of target file(s) inside *objects_dir*.  Returns
    ``True`` on full success or raises ``IPDSExtensionError`` on failure.

Environment variables (all optional, sensible defaults are provided)
--------------------------------------------------------------------
IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID
IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET
IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL
IPDS_RE_PRESERVATION_COGNITO_SCOPE
IPDS_RE_PRESERVATION_COGNITO_TIMEOUT
IPDS_RE_PRESERVATION_SERVICE_URL
IPDS_RE_PRESERVATION_SERVICE_HEADERS  (JSON dict)
IPDS_RE_PRESERVATION_DIGEST_ALGORITHM
IPDS_RE_PRESERVATION_TIMEOUT
IPDS_RE_PRESERVATION_VERIFY           (bool, default True)
IPDS_RE_PRESERVATION_RETRIES          (int, default 2)
IPDS_RE_PRESERVATION_BACKOFF_BASE     (int seconds, default 5)
IPDS_EXTENSION_EVENT_URL
IPDS_EXTENSION_EVENT_RETRIES
IPDS_EXTENSION_EVENT_BACKOFF_BASE
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time

import requests

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IPDSExtensionError(Exception):
    """Raised when the IPDS signature extension process fails."""


# ---------------------------------------------------------------------------
# In-process Cognito token cache (module-level singleton)
# Thread-safe via a lock to prevent concurrent token refreshes.
# ---------------------------------------------------------------------------

_cognito_token_lock = threading.Lock()
_cognito_token_cache: dict = {"access_token": None, "expiry_ts": 0.0}

# Allowlist of hash algorithms accepted for the IPDS extension event
_ALLOWED_HASH_ALGORITHMS = frozenset(
    {
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3224",
        "sha3256",
        "sha3384",
        "sha3512",
    }
)

# Maximum sleep time (seconds) between HTTP retry attempts
_MAX_BACKOFF_SLEEP = 60

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _env_str(name: str, default=None) -> str | None:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_json_dict(name: str, default=None) -> dict:
    raw = os.environ.get(name)
    if not raw:
        return {} if default is None else default
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else ({} if default is None else default)
    except Exception:
        logging.getLogger(__name__).warning(
            "Invalid JSON in environment variable %s: %r", name, raw
        )
        return {} if default is None else default


# ---------------------------------------------------------------------------
# Signature-level determination
# ---------------------------------------------------------------------------


def signature_level_for_file(file_name: str) -> str | None:
    """Return the DSS signatureLevel string for *file_name*, or ``None`` if
    the file type is not supported.
    """
    ext = os.path.splitext(file_name)[1].lower()
    if ext == ".pdf":
        return "PAdES_BASELINE_LTA"
    if ext == ".xml":
        return "XAdES_BASELINE_LTA"
    return None


# ---------------------------------------------------------------------------
# Cognito token
# ---------------------------------------------------------------------------

_DEFAULT_COGNITO_CLIENT_ID = ""
_DEFAULT_COGNITO_CLIENT_SECRET = ""
_DEFAULT_COGNITO_TOKEN_URL = ""
_DEFAULT_COGNITO_SCOPE = "dss/certificate-validation"


def fetch_cognito_token(logger=None, timeout: int | None = None) -> str | None:
    """Fetch (or return cached) an OAuth2 access-token from Cognito.

    Returns the *access_token* string, or ``None`` on failure.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    client_id = _env_str("IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID", _DEFAULT_COGNITO_CLIENT_ID)
    client_secret = _env_str(
        "IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET", _DEFAULT_COGNITO_CLIENT_SECRET
    )
    token_url = _env_str("IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL", _DEFAULT_COGNITO_TOKEN_URL)
    scope = _env_str("IPDS_RE_PRESERVATION_COGNITO_SCOPE", _DEFAULT_COGNITO_SCOPE)

    if not client_id or not client_secret or not token_url:
        return None

    now = time.time()
    with _cognito_token_lock:
        cached = _cognito_token_cache
        if cached.get("access_token") and cached.get("expiry_ts", 0) > now + 5:
            logger.debug("[ipds] using cached Cognito token")
            return cached["access_token"]

    try:
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {encoded}",
        }
        data: dict = {"grant_type": "client_credentials"}
        if scope:
            data["scope"] = scope

        request_timeout = timeout or _env_int("IPDS_RE_PRESERVATION_COGNITO_TIMEOUT", 10)
        verify = _env_bool("IPDS_RE_PRESERVATION_VERIFY", True)

        resp = requests.post(
            token_url,
            data=data,
            headers=headers,
            timeout=request_timeout,
            verify=verify,
        )
        resp.raise_for_status()

        j = resp.json()
        token = j.get("access_token")
        if not token:
            logger.error("[ipds] Cognito response did not include access_token")
            return None

        expires_in = j.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            expiry_ts = time.time() + float(expires_in)
        else:
            expiry_ts = time.time() + 55

        with _cognito_token_lock:
            _cognito_token_cache["access_token"] = token
            _cognito_token_cache["expiry_ts"] = expiry_ts

        logger.info("[ipds] obtained Cognito access token")
        return token

    except requests.exceptions.RequestException as exc:
        logger.error("[ipds] error fetching Cognito token: %s", exc)
        return None
    except Exception as exc:
        logger.error("[ipds] unexpected error fetching Cognito token: %s", exc)
        return None


# ---------------------------------------------------------------------------
# DSS datetime parsing
# ---------------------------------------------------------------------------


def _parse_dss_datetime(value) -> datetime.datetime | None:
    """Parse a DSS date value (ISO-8601 string or epoch-milliseconds int/float)."""
    try:
        if isinstance(value, (int, float)):
            return datetime.datetime.fromtimestamp(
                float(value) / 1000.0, tz=datetime.timezone.utc
            )
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# ExtensionPeriodMax extraction
# ---------------------------------------------------------------------------


def _extract_earliest_certificate_not_after(resp_json: dict) -> datetime.datetime | None:
    """Fallback: earliest certificate NotAfter from DSS DiagnosticData."""
    logger = logging.getLogger(__name__)
    if not resp_json or not isinstance(resp_json, dict):
        return None

    diagnostic = (
        resp_json.get("DiagnosticData")
        or resp_json.get("diagnosticData")
        or {}
    )
    if not isinstance(diagnostic, dict):
        return None

    certs = None
    used = diagnostic.get("UsedCertificates")
    if isinstance(used, dict):
        certs = used.get("Certificate")
    if certs is None:
        certs = diagnostic.get("Certificate")
    if isinstance(certs, dict):
        certs = [certs]
    elif not isinstance(certs, list):
        certs = []

    candidates = []
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        dt = _parse_dss_datetime(cert.get("NotAfter"))
        if dt is not None:
            candidates.append(dt)

    if not candidates:
        logger.info("[ipds] no certificate NotAfter found")
        return None

    earliest = min(candidates)
    logger.info("[ipds] fallback earliest certificate NotAfter=%s", earliest.isoformat())
    return earliest


def extract_extension_period_max(resp_json: dict) -> datetime.datetime | None:
    """Extract the earliest ExtensionPeriodMax from a DSS validation response.

    Falls back to the earliest certificate NotAfter if no ExtensionPeriodMax
    is present.
    """
    logger = logging.getLogger(__name__)
    if not resp_json or not isinstance(resp_json, dict):
        return None

    simple_report = (
        resp_json.get("SimpleReport")
        or resp_json.get("simpleReport")
        or resp_json.get("simple_report")
    )

    if not isinstance(simple_report, dict):
        return _extract_earliest_certificate_not_after(resp_json)

    entries = (
        simple_report.get("signatureOrTimestampOrEvidenceRecord")
        or simple_report.get("signatureOrTimestamp")
        or []
    )
    if isinstance(entries, dict):
        entries = [entries]
    elif not isinstance(entries, list):
        entries = []

    earliest = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        node = (
            entry.get("Signature")
            or entry.get("Timestamp")
            or entry.get("EvidenceRecord")
        )
        if not isinstance(node, dict):
            continue
        raw_value = node.get("ExtensionPeriodMax")
        if raw_value is None:
            continue
        candidate = _parse_dss_datetime(raw_value)
        if candidate is None:
            logger.warning("[ipds] could not parse ExtensionPeriodMax value: %r", raw_value)
            continue
        if earliest is None or candidate < earliest:
            earliest = candidate

    if earliest is not None:
        logger.info("[ipds] extracted ExtensionPeriodMax=%s", earliest.isoformat())
        return earliest

    return _extract_earliest_certificate_not_after(resp_json)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _build_auth_headers(base_headers: dict, logger) -> dict:
    """Ensure *base_headers* contains an Authorization header, fetching a
    Cognito token if needed.  Returns the (possibly updated) headers dict.
    """
    if any(k.lower() == "authorization" for k in base_headers):
        return base_headers
    token = fetch_cognito_token(logger=logger)
    if not token:
        raise IPDSExtensionError("failed to obtain Cognito access token")
    base_headers["Authorization"] = "Bearer " + token
    return base_headers


def _post_with_retry(
    url: str,
    payload: dict,
    headers: dict,
    timeout: int,
    verify: bool,
    max_retries: int,
    backoff_base: int,
    logger,
) -> requests.Response:
    """POST *payload* to *url* with retry on server errors."""
    attempt = 0
    resp = None
    while attempt < max_retries:
        attempt += 1
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=verify)
            if 500 <= getattr(resp, "status_code", 0) < 600:
                if attempt < max_retries:
                    sleep_for = min(backoff_base * (2 ** (attempt - 1)), _MAX_BACKOFF_SLEEP)
                    logger.warning(
                        "[ipds] HTTP %s from %s (attempt %d), retrying in %ds",
                        resp.status_code, url, attempt, sleep_for,
                    )
                    time.sleep(sleep_for)
                    continue
                resp.raise_for_status()
            else:
                resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as exc:
            should_retry = attempt < max_retries and (
                not isinstance(exc, requests.exceptions.HTTPError)
                or getattr(resp, "status_code", 0) >= 500
            )
            if should_retry:
                sleep_for = min(backoff_base * (2 ** (attempt - 1)), _MAX_BACKOFF_SLEEP)
                logger.warning("[ipds] request error (attempt %d): %s, retrying in %ds", attempt, exc, sleep_for)
                time.sleep(sleep_for)
                continue
            raise IPDSExtensionError(f"HTTP request to {url} failed: {exc}") from exc
    raise IPDSExtensionError(f"All {max_retries} attempts to {url} failed")


# ---------------------------------------------------------------------------
# Validate signature and extract ExtensionPeriodMax
# ---------------------------------------------------------------------------


def validate_signature_and_extract_period(
    extended_bytes: bytes,
    file_name: str,
    headers: dict,
    timeout: int,
    logger=None,
) -> datetime.datetime | None:
    """Send the extended document to the DSS validation endpoint and return
    the earliest ExtensionPeriodMax, or ``None`` if it cannot be determined.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    base_url = _env_str("IPDS_RE_PRESERVATION_SERVICE_URL")
    if base_url:
        validate_url = re.sub(
            r"/dss/services/rest/.+/extendDocument$",
            "/dss/services/rest/validation/validateSignature",
            base_url.rstrip("/"),
        )
        if validate_url == base_url.rstrip("/"):
            validate_url = base_url.rstrip("/") + "/dss/services/rest/validation/validateSignature"
    else:
        validate_url = _env_str("IPDS_RE_PRESERVATION_VALIDATE_URL", "")

    if not validate_url:
        logger.warning("[ipds] no validation URL configured; skipping signature validation")
        return None

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req_headers.update(headers)

    try:
        req_headers = _build_auth_headers(req_headers, logger)
    except IPDSExtensionError as exc:
        logger.warning("[ipds] could not add auth header for validation: %s", exc)

    encoded = base64.b64encode(extended_bytes).decode("ascii")
    payload = {"signedDocument": {"name": file_name, "bytes": encoded}}

    max_retries = _env_int("IPDS_RE_PRESERVATION_RETRIES", 2)
    backoff_base = _env_int("IPDS_RE_PRESERVATION_BACKOFF_BASE", 5)
    verify = _env_bool("IPDS_RE_PRESERVATION_VERIFY", True)

    try:
        resp = _post_with_retry(validate_url, payload, req_headers, timeout, verify, max_retries, backoff_base, logger)
        resp_json = resp.json()
    except IPDSExtensionError:
        raise
    except Exception as exc:
        logger.error("[ipds] validation call failed for '%s': %s", file_name, exc)
        return None

    return extract_extension_period_max(resp_json)


# ---------------------------------------------------------------------------
# Send extension event to IPDS
# ---------------------------------------------------------------------------


def send_extension_event(
    doc_id: str,
    period_dt: datetime.datetime,
    headers: dict,
    timeout: int,
    hash_value: str | None = None,
    file_size: int | None = None,
    digest_algorithm: str | None = None,
    logger=None,
) -> bool:
    """POST the extension event to the IPDS event endpoint.

    Returns ``True`` on success, ``False`` otherwise.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if not doc_id or not period_dt:
        logger.debug("[ipds] no doc_id or period_dt – skipping extension event")
        return False

    event_url = _env_str(
        "IPDS_EXTENSION_EVENT_URL",
        "",
    )
    if not event_url:
        logger.warning("[ipds] IPDS_EXTENSION_EVENT_URL not configured; skipping extension event")
        return False

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req_headers.update(headers)

    try:
        req_headers = _build_auth_headers(req_headers, logger)
    except IPDSExtensionError as exc:
        logger.warning("[ipds] could not add auth header for event post: %s", exc)

    payload: dict = {
        "ipdsDocId": str(doc_id),
        "extensionPeriodMax": period_dt.isoformat(),
    }
    if hash_value:
        payload["hash"] = hash_value
    if file_size is not None:
        payload["fileSize"] = int(file_size)
    if digest_algorithm:
        payload["digestAlgorithm"] = digest_algorithm

    max_retries = _env_int("IPDS_EXTENSION_EVENT_RETRIES", 2)
    backoff_base = _env_int("IPDS_EXTENSION_EVENT_BACKOFF_BASE", 5)
    verify = _env_bool("IPDS_RE_PRESERVATION_VERIFY", True)

    try:
        resp = _post_with_retry(
            event_url, payload, req_headers, timeout, verify, max_retries, backoff_base, logger
        )
        if resp.status_code >= 400:
            logger.warning("[ipds] extension event endpoint returned %s", resp.status_code)
            return False
        logger.info("[ipds] extension event sent for doc %s", doc_id)
        return True
    except IPDSExtensionError as exc:
        logger.error("[ipds] failed to send extension event: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Extend a single file
# ---------------------------------------------------------------------------


def _extend_single_file(
    file_path: str,
    ipds_doc_id: str,
    headers: dict,
    timeout: int,
    configured_digest: str,
    logger,
) -> None:
    """Call the extension service for one file, validate the result, write the
    extended bytes back and send the IPDS event.

    Raises :class:`IPDSExtensionError` on any failure.
    """
    file_name = os.path.basename(file_path)
    signature_level = signature_level_for_file(file_name)
    if not signature_level:
        raise IPDSExtensionError(
            f"unsupported file extension for '{file_name}' – cannot determine signatureLevel"
        )

    external_service_url = _env_str(
        "IPDS_RE_PRESERVATION_SERVICE_URL",
        "",
    )
    if not external_service_url:
        raise IPDSExtensionError(
            "IPDS_RE_PRESERVATION_SERVICE_URL is not configured; cannot extend signatures"
        )
    service_headers = _env_json_dict("IPDS_RE_PRESERVATION_SERVICE_HEADERS", {})
    verify = _env_bool("IPDS_RE_PRESERVATION_VERIFY", True)
    max_retries = _env_int("IPDS_RE_PRESERVATION_RETRIES", 2)
    backoff_base = _env_int("IPDS_RE_PRESERVATION_BACKOFF_BASE", 5)

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req_headers.update(service_headers)
    req_headers = _build_auth_headers(req_headers, logger)

    with open(file_path, "rb") as fh:
        original_bytes = fh.read()

    file_bytes_b64 = base64.b64encode(original_bytes).decode("ascii")
    payload = {
        "toExtendDocument": {"bytes": file_bytes_b64, "name": file_name},
        "parameters": {"signatureLevel": signature_level},
    }

    logger.info("[ipds] sending '%s' to %s", file_name, external_service_url)
    resp = _post_with_retry(
        external_service_url, payload, req_headers, timeout, verify, max_retries, backoff_base, logger
    )

    try:
        resp_json = resp.json()
    except Exception as exc:
        raise IPDSExtensionError(
            f"failed to parse JSON response for '{file_name}': {exc}"
        ) from exc

    extended_b64 = resp_json.get("bytes") or (resp_json.get("document") or {}).get("bytes")
    if not extended_b64:
        raise IPDSExtensionError(
            f"no 'bytes' field in extension response for '{file_name}'. "
            f"Response keys: {list(resp_json.keys())}"
        )

    try:
        extended_bytes = base64.b64decode(extended_b64)
    except Exception as exc:
        raise IPDSExtensionError(
            f"failed to decode extended bytes for '{file_name}': {exc}"
        ) from exc

    # Write extended document back to disk atomically (temp file + rename)
    dir_name = os.path.dirname(file_path)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".ipds_ext_")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(extended_bytes)
            os.replace(tmp_path, file_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except IPDSExtensionError:
        raise
    except Exception as exc:
        raise IPDSExtensionError(
            f"failed to write extended document to '{file_path}': {exc}"
        ) from exc

    logger.info("[ipds] '%s' replaced with extended-signature version (%d bytes)", file_name, len(extended_bytes))

    # Validate and extract ExtensionPeriodMax
    period = validate_signature_and_extract_period(
        extended_bytes, file_name, headers=req_headers, timeout=timeout, logger=logger
    )
    if period is None:
        raise IPDSExtensionError(
            f"could not extract ExtensionPeriodMax for '{file_name}' after extension"
        )
    logger.info("[ipds] ExtensionPeriodMax for '%s': %s", file_name, period.isoformat())

    # Compute hash for the event (validate algorithm against allowlist)
    try:
        raw_algorithm = (configured_digest.lower().replace("-", "").replace("_", "")) if configured_digest else "sha256"
        algorithm = raw_algorithm if raw_algorithm in _ALLOWED_HASH_ALGORITHMS else "sha256"
        if raw_algorithm and raw_algorithm not in _ALLOWED_HASH_ALGORITHMS:
            logger.warning(
                "[ipds] unsupported digest algorithm '%s'; falling back to sha256",
                configured_digest,
            )
        h = hashlib.new(algorithm)
        h.update(extended_bytes)
        hash_hex = h.hexdigest()
        file_size = len(extended_bytes)
    except Exception as exc:
        logger.warning("[ipds] could not compute hash/filesize for '%s': %s", file_name, exc)
        hash_hex = None
        file_size = None

    sent = send_extension_event(
        doc_id=ipds_doc_id,
        period_dt=period,
        headers=req_headers,
        timeout=timeout,
        hash_value=hash_hex,
        file_size=file_size,
        digest_algorithm=configured_digest,
        logger=logger,
    )
    if not sent:
        raise IPDSExtensionError(f"failed to send extension event for '{file_name}'")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extend_aip_objects(
    objects_dir: str,
    ipds_doc_name: str = "",
    ipds_doc_id: str = "",
    logger=None,
) -> bool:
    """Extend the IPDS signatures of target file(s) inside *objects_dir*.

    Parameters
    ----------
    objects_dir:
        Absolute path to the ``data/objects`` (or ``objects``) directory of
        the working AIP copy.
    ipds_doc_name:
        If non-empty, only the file with this basename is processed.  If
        empty, all supported files in *objects_dir* are processed.
    ipds_doc_id:
        IPDS document identifier used when sending the extension event.  If
        empty, the call to the event endpoint is still made but with an empty
        id (the event endpoint must accept it or this will raise).
    logger:
        Optional standard-library logger.  A module-level logger is used when
        not provided.

    Returns
    -------
    ``True`` on full success.

    Raises
    ------
    :class:`IPDSExtensionError`
        On any failure (service unavailable, validation failure, event
        failure).  The caller is expected to propagate this as a fatal error.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if not os.path.isdir(objects_dir):
        raise IPDSExtensionError(f"objects directory not found: {objects_dir}")

    all_files = sorted(
        os.path.join(objects_dir, f)
        for f in os.listdir(objects_dir)
        if os.path.isfile(os.path.join(objects_dir, f))
    )

    if not all_files:
        raise IPDSExtensionError(f"no files found in objects directory: {objects_dir}")

    if ipds_doc_name:
        target_files = [fp for fp in all_files if os.path.basename(fp) == ipds_doc_name]
        if not target_files:
            raise IPDSExtensionError(
                f"no file matching ipds-doc-name='{ipds_doc_name}' found in {objects_dir}"
            )
        logger.info("[ipds] targeting single file: %s", ipds_doc_name)
    else:
        target_files = all_files
        logger.info("[ipds] no ipds-doc-name set; targeting all %d file(s)", len(target_files))

    timeout = _env_int("IPDS_RE_PRESERVATION_TIMEOUT", 60)
    configured_digest = _env_str("IPDS_RE_PRESERVATION_DIGEST_ALGORITHM", "SHA256")

    for file_path in target_files:
        _extend_single_file(
            file_path=file_path,
            ipds_doc_id=ipds_doc_id,
            headers={},
            timeout=timeout,
            configured_digest=configured_digest,
            logger=logger,
        )

    logger.info("[ipds] all targeted files extended successfully")
    return True
