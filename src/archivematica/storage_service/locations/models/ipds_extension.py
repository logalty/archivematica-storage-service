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

Environment variables
---------------------
Required (the Storage Service refuses to start without them, see
``ensure_cognito_settings``; there is no default, the secret must come from the
deployment Secret and never from the code):

IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID
IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET
IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL

Optional (sensible defaults are provided):

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
IPDS_EXTENSION_EVENT_RETRIES          (int, default 3)
IPDS_EXTENSION_EVENT_BACKOFF_BASE
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import json
import logging
import os
import re
from typing import Dict, Optional
import tempfile
import threading
import time
import zipfile

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
    if ext == ".json":
        return "JAdES_BASELINE_LTA"
    return "CAdES_BASELINE_LTA"


# ---------------------------------------------------------------------------
# Objects that carry only RFC 3161 timestamps (IPDS-853)
# ---------------------------------------------------------------------------
#
# DSS extendDocument extends SIGNATURES only. A PDF whose signature dictionaries are all
# document timestamps fails with "No signatures found to be extended!", and an ASiC
# container holding only timestamp tokens fails with "No supported signature documents
# found!". Those objects are renewed with timestampDocument: DSS embeds the validation
# data of the existing timestamps and adds a new timestamp over everything (PDF: an
# incremental revision with /DSS and a new DocTimeStamp; ASiC: an ASiCArchiveManifest
# and a new META-INF/timestampNNN.tst). The detection reads the content only and answers
# "timestamp-only" solely when it is certain; anything else keeps the extendDocument path.

_TIMESTAMP_DIGEST_ALGORITHM = "SHA256"
_PDF_TIMESTAMP_SUBFILTER = b"ETSI.RFC3161"
_PDF_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
_PDF_SUBFILTER = re.compile(rb"/SubFilter\s*/([^\s/<>\[\]()]+)")
_PDF_HEX_STRING = re.compile(rb"\s*<[0-9A-Fa-f\s]*>\s*")
_ASIC_MIMETYPES = {
    "ASiC_S": "application/vnd.etsi.asic-s+zip",
    "ASiC_E": "application/vnd.etsi.asic-e+zip",
}
_ASIC_FORM_BY_EXTENSION = {".asics": "ASiC_S", ".scs": "ASiC_S", ".asice": "ASiC_E", ".sce": "ASiC_E"}
_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
_OID_TST_INFO = bytes.fromhex("2a864886f70d0109100104")  # 1.2.840.113549.1.9.16.1.4


def _pdf_signature_subfilters(data: bytes) -> list | None:
    """SubFilter of every signature dictionary (signature or document timestamp) of the PDF *data*.

    A signature dictionary is found through its /ByteRange, which must describe this very file: it starts at 0, stays
    inside the file and leaves out exactly a hex string (its /Contents). Returns ``None`` when any /ByteRange or its
    SubFilter cannot be read that way (an embedded file, an unusual writer): the caller must not guess then.
    """
    if b"%PDF-" not in data[:1024]:
        return None
    matches = list(_PDF_BYTE_RANGE.finditer(data))
    if len(matches) != data.count(b"/ByteRange"):
        return None
    subfilters = []
    for match in matches:
        start1, length1, start2, length2 = (int(group) for group in match.groups())
        if start1 != 0 or not 0 < length1 < start2 or start2 + length2 > len(data):
            return None
        if not _PDF_HEX_STRING.fullmatch(data, length1, start2):
            return None
        object_start = data.rfind(b"obj", 0, min(match.start(), length1))
        object_end = data.find(b"endobj", max(match.end(), start2))
        if object_start < 0 or object_end < 0:
            return None
        names = _PDF_SUBFILTER.findall(data, object_start, object_end)
        if len(names) != 1:
            return None
        subfilters.append(names[0])
    return subfilters


def _der_element(data: bytes, pos: int, end: int) -> tuple:
    """``(tag, value_start, value_end)`` of the definite-length DER element at *pos*; ValueError otherwise."""
    if pos + 2 > end:
        raise ValueError("truncated DER element")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        if not 0 < size <= 4 or pos + size > end:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    if pos + length > end:
        raise ValueError("truncated DER element")
    return tag, pos, pos + length


def _der_children(data: bytes, start: int, end: int) -> list:
    children = []
    while start < end:
        child = _der_element(data, start, end)
        children.append(child)
        start = child[2]
    return children


def _timestamp_token_tst_info(token: bytes) -> bytes | None:
    """The DER TSTInfo of an RFC 3161 timestamp token (CMS SignedData over id-ct-TSTInfo), or ``None``.

    DSS rewrites an existing token when it renews a container (it adds the validation data to the SignedData), so the
    file hash changes; the TSTInfo, which is what the TSA signed, must not.
    """
    try:
        tag, start, end = _der_element(token, 0, len(token))
        content_type, content = _der_children(token, start, end)[:2]
        if tag != 0x30 or token[content_type[1]:content_type[2]] != _OID_SIGNED_DATA or content[0] != 0xA0:
            return None
        _, start, end = _der_element(token, content[1], content[2])
        encapsulated = _der_children(token, start, end)[2]  # version, digestAlgorithms, encapContentInfo
        econtent_type, econtent = _der_children(token, encapsulated[1], encapsulated[2])[:2]
        if token[econtent_type[1]:econtent_type[2]] != _OID_TST_INFO or econtent[0] != 0xA0:
            return None
        tag, start, end = _der_element(token, econtent[1], econtent[2])
        return token[start:end] if tag == 0x04 else None
    except (ValueError, IndexError):
        return None


def _read_asic(data: bytes) -> dict | None:
    """What the renewal needs from an ASiC container, or ``None`` if *data* is not a readable ZIP.

    Entry names follow DSS 6.5 ``ASiCUtils``: a timestamp is ``META-INF/`` + "timestamp" + ``.tst``. Signatures and
    evidence records are matched more broadly (any ``META-INF/`` entry naming them, any case) so that a doubtful
    container is never taken for timestamp-only.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if zf.testzip() is not None:
                return None
            names = zf.namelist()
            meta = [n for n in names if n.startswith("META-INF/")]
            return {
                "mimetype": zf.read("mimetype").decode("utf-8").strip() if "mimetype" in names else None,
                "documents": {
                    n: hashlib.sha256(zf.read(n)).hexdigest()
                    for n in names
                    if n != "mimetype" and not n.startswith("META-INF/") and not n.endswith("/")
                },
                "timestamps": {
                    n: _timestamp_token_tst_info(zf.read(n))
                    for n in meta
                    if "timestamp" in n and n.endswith(".tst")
                },
                "signed": any("signature" in n.lower() or "evidencerecord" in n.lower() for n in meta),
            }
    except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, OSError, UnicodeDecodeError, ValueError):
        return None


def _asic_form(asic: dict, file_name: str) -> str | None:
    """``ASiC_S``/``ASiC_E`` from the file extension and the ``mimetype`` entry; ``None`` if unknown or in conflict."""
    by_extension = _ASIC_FORM_BY_EXTENSION.get(os.path.splitext(file_name)[1].lower())
    by_mimetype = None
    if asic["mimetype"] is not None:
        by_mimetype = next((form for form, mime in _ASIC_MIMETYPES.items() if mime == asic["mimetype"]), None)
        if by_mimetype is None:
            return None
    if by_extension and by_mimetype and by_extension != by_mimetype:
        return None
    return by_extension or by_mimetype


def timestamp_only_form(data: bytes, file_name: str) -> str | None:
    """The DSS ``timestampContainerForm`` that renews *data* when it carries only RFC 3161 timestamps, else ``None``.

    ``PDF``: at least one signature dictionary and all of them with SubFilter ``/ETSI.RFC3161`` (document timestamps).
    ``ASiC_S``/``ASiC_E``: a container with RFC 3161 tokens in ``META-INF/*timestamp*.tst``, no signature or evidence
    record entry and signed data to cover. Signed objects, unsigned ones and anything that cannot be classified with
    certainty return ``None`` and keep the extendDocument path.
    """
    if data.startswith(b"PK\x03\x04"):
        # A ZIP first: a stored PDF inside a container also shows "%PDF-" in its first bytes.
        asic = _read_asic(data)
        if asic is None or asic["signed"] or not asic["timestamps"] or not asic["documents"]:
            return None
        if any(tst_info is None for tst_info in asic["timestamps"].values()):
            return None
        form = _asic_form(asic, file_name)
        if form == "ASiC_S" and len(asic["documents"]) != 1:
            return None
        return form
    subfilters = _pdf_signature_subfilters(data)
    if subfilters and all(name == _PDF_TIMESTAMP_SUBFILTER for name in subfilters):
        return "PDF"
    return None


def _verify_timestamp_renewal(original: bytes, renewed: bytes, form: str, file_name: str) -> None:
    """Check the DSS result of a timestamp renewal before it replaces *original*; raise IPDSExtensionError if not.

    PDF: an incremental update (the original is an exact prefix) that adds document timestamps and no signature.
    ASiC: still a valid ZIP with the right mimetype, the same signed data (same names and SHA-256), every original
    token still there with the same TSTInfo, and at least one new token.
    """
    rejected = f"timestamp renewal of '{file_name}' rejected before writing it:"
    if form == "PDF":
        if len(renewed) <= len(original) or not renewed.startswith(original):
            raise IPDSExtensionError(f"{rejected} the original PDF is not an exact prefix of the DSS result")
        before = _pdf_signature_subfilters(original) or []
        after = _pdf_signature_subfilters(renewed)
        if after is None or any(name != _PDF_TIMESTAMP_SUBFILTER for name in after) or len(after) <= len(before):
            raise IPDSExtensionError(f"{rejected} the DSS result does not add a document timestamp")
        return

    before = _read_asic(original)
    after = _read_asic(renewed)
    if before is None or after is None:
        raise IPDSExtensionError(f"{rejected} the DSS result is not a valid ZIP container")
    expected_mimetype = before["mimetype"] or _ASIC_MIMETYPES[form]
    if after["mimetype"] != expected_mimetype and not (before["mimetype"] is None and after["mimetype"] is None):
        raise IPDSExtensionError(
            f"{rejected} mimetype {after['mimetype']!r} instead of {expected_mimetype!r}"
        )
    if after["documents"] != before["documents"]:
        raise IPDSExtensionError(f"{rejected} the signed data inside the container changed")
    for name, tst_info in before["timestamps"].items():
        if after["timestamps"].get(name) != tst_info:
            raise IPDSExtensionError(f"{rejected} the original timestamp '{name}' is missing or changed")
    if after["signed"]:
        raise IPDSExtensionError(f"{rejected} the DSS result holds a signature or evidence record entry")
    if not set(after["timestamps"]) - set(before["timestamps"]):
        raise IPDSExtensionError(f"{rejected} the DSS result does not add a timestamp token")


# ---------------------------------------------------------------------------
# Cognito token
# ---------------------------------------------------------------------------

_DEFAULT_COGNITO_SCOPE = "dss/certificate-validation"

# Settings without which no Cognito token can be requested. They have no default on purpose (IPDS-902): a
# client secret written in the code is a leaked secret.
COGNITO_REQUIRED_ENV = (
    "IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID",
    "IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET",
    "IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL",
)


def missing_cognito_settings() -> list[str]:
    """Names (never values) of the required Cognito variables that are unset or blank."""
    return [name for name in COGNITO_REQUIRED_ENV if not (_env_str(name) or "").strip()]


def ensure_cognito_settings() -> None:
    """Fail fast, at startup, when the Cognito settings are not configured."""
    missing = missing_cognito_settings()
    if missing:
        raise IPDSExtensionError(
            "IPDS signature extension is not configured: missing environment variable(s) " + ", ".join(missing)
        )


def fetch_cognito_token(logger=None, timeout: int | None = None) -> str | None:
    """Fetch (or return cached) an OAuth2 access-token from Cognito.

    Returns the *access_token* string, or ``None`` on failure.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    missing = missing_cognito_settings()
    if missing:
        logger.error("[ipds] Cognito is not configured, missing: %s", ", ".join(missing))
        return None

    client_id = _env_str("IPDS_RE_PRESERVATION_COGNITO_CLIENT_ID")
    client_secret = _env_str("IPDS_RE_PRESERVATION_COGNITO_CLIENT_SECRET")
    token_url = _env_str("IPDS_RE_PRESERVATION_COGNITO_TOKEN_URL")
    scope = _env_str("IPDS_RE_PRESERVATION_COGNITO_SCOPE", _DEFAULT_COGNITO_SCOPE)

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


def _latest_timestamp_period(entries: list) -> datetime.datetime | None:
    """ExtensionPeriodMax of the most recent top-level ``Timestamp`` entry (by ProductionTime), or ``None``.

    Ties on ProductionTime keep the earliest ExtensionPeriodMax.
    """
    candidates = []
    for entry in entries:
        node = entry.get("Timestamp") if isinstance(entry, dict) else None
        if not isinstance(node, dict):
            continue
        produced = _parse_dss_datetime(node.get("ProductionTime"))
        period = _parse_dss_datetime(node.get("ExtensionPeriodMax"))
        if produced is not None and period is not None:
            candidates.append((produced, period))
    if not candidates:
        return None
    newest = max(produced for produced, _ in candidates)
    return min(period for produced, period in candidates if produced == newest)


def extract_extension_period_max(resp_json: dict, latest_timestamp: bool = False) -> datetime.datetime | None:
    """Extract the earliest ExtensionPeriodMax from a DSS validation response.

    Falls back to the earliest certificate NotAfter if no ExtensionPeriodMax
    is present.

    IPDS-853: with ``latest_timestamp`` (an object that carries only timestamps, just renewed) the date is the
    ExtensionPeriodMax of the most recent timestamp, which covers the earlier ones: an older TSU certificate must not
    bring the next renewal forward. Without a dated ``Timestamp`` entry it falls back to the rule above.
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

    if latest_timestamp:
        latest = _latest_timestamp_period(entries)
        if latest is not None:
            logger.info("[ipds] extracted ExtensionPeriodMax=%s from the most recent timestamp", latest.isoformat())
            return latest

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


# IPDS-894: DSS signature format of the extended document.
_FORMAT_LEVEL_RANK = {"B": 1, "T": 2, "LT": 3, "LTA": 4}
_MAX_SIGNATURE_FORMAT_LENGTH = 64


def _signature_format_rank(signature_format: str) -> int:
    """Rank a DSS signature format by its ETSI baseline level (``PAdES-BASELINE-LT`` -> 3).

    A format that is not a baseline profile (``PDF-NOT-ETSI``, ``XML-NOT-ETSI``, ``CMS-NOT-ETSI``...) ranks 0, below
    ``B``: it carries no ETSI guarantee at all.
    """
    match = re.search(r"-BASELINE-(LTA|LT|T|B)$", signature_format)
    return _FORMAT_LEVEL_RANK[match.group(1)] if match else 0


def extract_signature_format(resp_json: dict) -> Optional[str]:
    """Return the DSS ``SignatureFormat`` of the signatures in a validation response, or ``None``.

    Reads the same ``SimpleReport`` entries as :func:`extract_extension_period_max` and only looks at ``Signature``
    nodes (a ``Timestamp`` or ``EvidenceRecord`` node has no signature format). Only a value DSS actually returned is
    used: nothing is inferred from the level that was requested.

    Several signatures: the document is reported with the format of its WEAKEST signature (lowest baseline level; a
    non-baseline format counts as lower than ``B``; on a tie, the first one in report order). This is the same
    conservative rule as the earliest ``ExtensionPeriodMax``: the profile of the document is only as good as its
    least preserved signature, so one that failed to reach LTA is not hidden behind one that did.
    """
    if not resp_json or not isinstance(resp_json, dict):
        return None
    simple_report = (
            resp_json.get("SimpleReport")
            or resp_json.get("simpleReport")
            or resp_json.get("simple_report")
    )
    if not isinstance(simple_report, dict):
        return None
    entries = (
            simple_report.get("signatureOrTimestampOrEvidenceRecord")
            or simple_report.get("signatureOrTimestamp")
            or []
    )
    if isinstance(entries, dict):
        entries = [entries]
    elif not isinstance(entries, list):
        return None

    weakest = None
    for entry in entries:
        node = entry.get("Signature") if isinstance(entry, dict) else None
        if not isinstance(node, dict):
            continue
        value = node.get("SignatureFormat")
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value or len(value) > _MAX_SIGNATURE_FORMAT_LENGTH:
            continue
        if weakest is None or _signature_format_rank(value) < _signature_format_rank(weakest):
            weakest = value
    return weakest


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
        latest_timestamp: bool = False,
        signature_format_out: Optional[Dict] = None,
) -> datetime.datetime | None:
    """Send the extended document to the DSS validation endpoint and return
    the earliest ExtensionPeriodMax, or ``None`` if it cannot be determined.

    ``latest_timestamp``: see :func:`extract_extension_period_max` (IPDS-853).

    ``signature_format_out`` (IPDS-894): when given, the DSS ``SignatureFormat`` of the validated document is stored in
    it under ``"signatureFormat"`` (see :func:`extract_signature_format`). The key is left out when DSS returned none,
    so the return value and every error path stay as they were.
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
        validate_url = _env_str("IPDS_RE_PRESERVATION_VALIDATE_URL", "https://desarrollo.logalty.com/dss/services/rest/validation/validateSignature")

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

    if signature_format_out is not None:
        signature_format = extract_signature_format(resp_json)
        if signature_format:
            signature_format_out["signatureFormat"] = signature_format
        else:
            logger.warning("[ipds] DSS returned no SignatureFormat for '%s'; the event will not carry it", file_name)

    return extract_extension_period_max(resp_json, latest_timestamp=latest_timestamp)


# ---------------------------------------------------------------------------
# Send extension event to IPDS
# ---------------------------------------------------------------------------


def send_extension_event(
        doc_id: str,
        period_dt: datetime.datetime | None = None,
        headers: dict | None = None,
        timeout: int = 30,
        hash_value: str | None = None,
        file_size: int | None = None,
        digest_algorithm: str | None = None,
        logger=None,
        error: str | None = None,
        signature_format: str | None = None,
) -> bool:
    """POST the extension event to the IPDS event endpoint.

    IPDS-894: ``signature_format`` is the DSS ``SignatureFormat`` of the extended document, as DSS validated it. It is
    optional on the IPDS side and is only sent when there is a value.

    IPDS-831: ``error`` marks a FAILURE event. IPDS treats an event without ``extensionPeriodMax``, ``hash`` and
    ``fileSize`` as a failed extension, records ``ipds failed extension`` and raises the operator alarm; the message
    travels in ``error`` so both say why.

    Returns ``True`` on success, ``False`` otherwise.
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if not doc_id:
        logger.debug("[ipds] no doc_id – skipping extension event")
        return False

    event_url = _env_str(
        "IPDS_EXTENSION_EVENT_URL",
        "https://ipds-dev.logalty.com/services/api/event/signature/extension",
    )
    if not event_url:
        logger.warning("[ipds] IPDS_EXTENSION_EVENT_URL not configured; skipping extension event")
        return False

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}

    if headers:
        req_headers.update(headers)

    try:
        req_headers = _build_auth_headers(req_headers, logger)
    except IPDSExtensionError as exc:
        logger.warning("[ipds] could not add auth header for event post: %s", exc)

    payload: dict = {
        "ipdsDocId": str(doc_id),
    }
    if period_dt is not None:
        payload["extensionPeriodMax"] = period_dt.isoformat()
    if hash_value:
        payload["hash"] = hash_value
    if file_size is not None:
        payload["fileSize"] = int(file_size)
    if digest_algorithm:
        payload["digestAlgorithm"] = digest_algorithm
    if error:
        payload["error"] = str(error)[:500]
    if signature_format:
        payload["signatureFormat"] = signature_format

    # IPDS-460: a reingest is fail-closed when the authoritative event cannot
    # be persisted. Retry the event three times before returning failure.
    max_retries = _env_int("IPDS_EXTENSION_EVENT_RETRIES", 3)
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
) -> tuple:
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
        "https://desarrollo.logalty.com/dss/services/rest/signature/one-document/extendDocument",
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
    # IPDS-853: an object that carries only RFC 3161 timestamps has no signature to extend; it is renewed with
    # timestampDocument, which sits next to extendDocument in the same DSS service.
    timestamp_form = timestamp_only_form(original_bytes, file_name)
    if timestamp_form:
        service_url = re.sub(r"/extendDocument$", "/timestampDocument", external_service_url.rstrip("/"))
        if not service_url.endswith("/timestampDocument"):
            raise IPDSExtensionError(
                f"'{file_name}' carries only timestamps but the timestampDocument URL cannot be derived from "
                f"IPDS_RE_PRESERVATION_SERVICE_URL={external_service_url!r} (it must end in /extendDocument)"
            )
        payload = {
            "toTimestampDocument": {"bytes": file_bytes_b64, "name": file_name},
            "timestampParameters": {
                "timestampContainerForm": timestamp_form,
                "digestAlgorithm": _TIMESTAMP_DIGEST_ALGORITHM,
            },
        }
        logger.info("[ipds] '%s' carries only RFC 3161 timestamps (%s): renewing it with a new timestamp",
                    file_name, timestamp_form)
    else:
        service_url = external_service_url
        payload = {
            "toExtendDocument": {"bytes": file_bytes_b64, "name": file_name},
            "parameters": {"signatureLevel": signature_level},
        }

    logger.info("[ipds] sending '%s' to %s", file_name, service_url)
    resp = _post_with_retry(
        service_url, payload, req_headers, timeout, verify, max_retries, backoff_base, logger
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

    if timestamp_form:
        _verify_timestamp_renewal(original_bytes, extended_bytes, timestamp_form, file_name)

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
    # IPDS-894: the resulting profile is only reported for a signature extension; a timestamp renewal has no signature.
    format_out = None if timestamp_form else {}
    period = validate_signature_and_extract_period(
        extended_bytes, file_name, headers=req_headers, timeout=timeout, logger=logger,
        latest_timestamp=bool(timestamp_form), signature_format_out=format_out,
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
        signature_format=(format_out or {}).get("signatureFormat"),
    )
    if not sent:
        logger.info("[ipds]❌❌ Error extension event not sent for '%s'", file_name)
        raise IPDSExtensionError(f"failed to send extension event for '{file_name}'")

    return hash_hex, algorithm


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extend_aip_objects(
        objects_dir: str,
        ipds_doc_name: str = "",
        ipds_doc_id: str = "",
        logger=None,
) -> dict:
    """Extend the IPDS signatures of target file(s) inside *objects_dir*.

    IPDS-831: any :class:`IPDSExtensionError` is reported to IPDS (a failure event with the message) before it is
    raised again, so a failed extension is no longer visible only in this service's log. Reporting is best effort and
    never hides the original error.
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    try:
        return _extend_aip_objects(objects_dir, ipds_doc_name, ipds_doc_id, logger)
    except IPDSExtensionError as exc:
        _report_extension_failure(ipds_doc_id, exc, logger)
        raise


def _report_extension_failure(ipds_doc_id: str, exc: Exception, logger) -> None:
    """Tell IPDS that the extension failed; never raises."""
    try:
        sent = send_extension_event(
            doc_id=ipds_doc_id,
            timeout=_env_int("IPDS_RE_PRESERVATION_TIMEOUT", 60),
            logger=logger,
            error=str(exc) or exc.__class__.__name__,
        )
        if not sent:
            logger.error("[ipds] the extension failure event for doc %s could not be delivered to IPDS", ipds_doc_id)
    except Exception as report_exc:  # noqa: BLE001 - reporting must not mask the original failure
        logger.error("[ipds] could not report the extension failure for doc %s: %s", ipds_doc_id, report_exc)


def _extend_aip_objects(
        objects_dir: str,
        ipds_doc_name: str,
        ipds_doc_id: str,
        logger,
) -> dict:
    """Extend the IPDS signatures of target file(s) inside *objects_dir* (see :func:`extend_aip_objects`).

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
    dict mapping absolute file path to ``(checksum_hex, algorithm)`` for each
    successfully extended file.

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

    results = {}
    for file_path in target_files:
        hash_hex, algorithm = _extend_single_file(
            file_path=file_path,
            ipds_doc_id=ipds_doc_id,
            headers={},
            timeout=timeout,
            configured_digest=configured_digest,
            logger=logger,
        )
        results[file_path] = (hash_hex, algorithm)

    logger.info("[ipds] all targeted files extended successfully")
    return results
