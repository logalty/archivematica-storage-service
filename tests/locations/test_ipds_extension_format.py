"""IPDS-894: the extension event carries the signature format DSS validated on the extended document.

The module is loaded by path (see test_ipds_extension.py): it needs only the standard library and ``requests``.
These tests run the real ``_extend_single_file``, ``validate_signature_and_extract_period`` and
``send_extension_event``; only the HTTP layer is replaced, so the DSS responses below are what decides the payload
that would reach ipds-api.
"""

import base64
import importlib.util
import logging
import pathlib
from unittest import mock

import pytest

_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "src"
    / "archivematica"
    / "storage_service"
    / "locations"
    / "models"
    / "ipds_extension.py"
)
_EXTEND_URL = "https://dss.example.invalid/dss/services/rest/signature/one-document/extendDocument"
_EVENT_URL = "https://ipds.example.invalid/services/api/event/signature/extension"
_PERIOD = "2036-04-26T10:57:08Z"


@pytest.fixture(scope="module")
def ext():
    spec = importlib.util.spec_from_file_location("ipds_extension_format_under_test", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _signature(signature_format=None, period=_PERIOD):
    node = {"ExtensionPeriodMax": period}
    if signature_format is not None:
        node["SignatureFormat"] = signature_format
    return {"Signature": node}


def _validation(*entries):
    return {"SimpleReport": {"signatureOrTimestampOrEvidenceRecord": list(entries)}}


def _http(body):
    response = mock.Mock()
    response.status_code = 200
    response.json.return_value = body
    return response


def _run(ext, monkeypatch, tmp_path, validation, file_name="doc.pdf", timestamp_form=None):
    """Run the extension of one file; return (event payload or None, requests made, logger records)."""
    monkeypatch.setenv("IPDS_RE_PRESERVATION_SERVICE_URL", _EXTEND_URL)
    monkeypatch.setenv("IPDS_EXTENSION_EVENT_URL", _EVENT_URL)
    path = tmp_path / file_name
    path.write_bytes(b"original")
    extended = b"extended-document"
    requests_made = []

    def fake_post(url, payload, *args, **kwargs):
        requests_made.append((url, payload))
        if url == _EXTEND_URL or url.endswith("/timestampDocument"):
            return _http({"bytes": base64.b64encode(extended).decode("ascii")})
        if url.endswith("/validation/validateSignature"):
            return _http(validation)
        assert url == _EVENT_URL, url
        return _http({})

    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger("ipds-894-test")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        with (
            mock.patch.object(ext, "_build_auth_headers", side_effect=lambda headers, log: headers),
            mock.patch.object(ext, "_post_with_retry", side_effect=fake_post),
            mock.patch.object(ext, "timestamp_only_form", return_value=timestamp_form),
            mock.patch.object(ext, "_verify_timestamp_renewal"),
        ):
            ext._extend_single_file(str(path), "doc-id-894", {}, 5, "SHA256", logger)
    finally:
        logger.removeHandler(handler)
    events = [payload for url, payload in requests_made if url == _EVENT_URL]
    assert len(events) == 1
    return events[0], requests_made, records


def test_the_format_dss_validated_is_sent(ext, monkeypatch, tmp_path):
    event, _, _ = _run(ext, monkeypatch, tmp_path, _validation(_signature("PAdES-BASELINE-LTA")))

    assert event["signatureFormat"] == "PAdES-BASELINE-LTA"
    # the rest of the payload is the one IPDS already knew
    assert set(event) == {
        "ipdsDocId", "extensionPeriodMax", "hash", "fileSize", "digestAlgorithm", "signatureFormat",
    }


def test_the_format_validated_wins_over_the_level_requested(ext, monkeypatch, tmp_path):
    # A .pdf is asked for PAdES-BASELINE-LTA; DSS validated the result as LT: the event says LT.
    event, requests_made, _ = _run(ext, monkeypatch, tmp_path, _validation(_signature("PAdES-BASELINE-LT")))

    assert requests_made[0][1]["parameters"]["signatureLevel"] == "PAdES_BASELINE_LTA"
    assert event["signatureFormat"] == "PAdES-BASELINE-LT"


@pytest.mark.parametrize(
    "validation",
    [
        _validation(_signature()),
        _validation(_signature("")),
        _validation(_signature("   ")),
        _validation(_signature(123)),
        _validation({"Timestamp": {"ExtensionPeriodMax": _PERIOD}}),
        _validation(),
        {"SimpleReport": {"signatureOrTimestampOrEvidenceRecord": []}, "certificates": []},
    ],
    ids=["no-field", "empty", "blank", "not-a-string", "only-timestamp", "no-entries", "empty-report"],
)
def test_no_format_from_dss_means_no_field(ext, monkeypatch, tmp_path, validation):
    # An ExtensionPeriodMax is needed for the extension to succeed; give one through a certificate fallback when the
    # report has none, so only the format is missing.
    if not any(
        isinstance(entry, dict) and "ExtensionPeriodMax" in next(iter(entry.values()))
        for entry in validation["SimpleReport"]["signatureOrTimestampOrEvidenceRecord"]
    ):
        validation = dict(validation)
        validation["SimpleReport"] = {
            "signatureOrTimestampOrEvidenceRecord": validation["SimpleReport"]["signatureOrTimestampOrEvidenceRecord"]
            + [{"Signature": {"ExtensionPeriodMax": _PERIOD}}]
        }

    event, _, records = _run(ext, monkeypatch, tmp_path, validation)

    assert "signatureFormat" not in event
    assert event["extensionPeriodMax"]
    assert any("no SignatureFormat" in record.getMessage() for record in records)


@pytest.mark.parametrize(
    "formats, expected",
    [
        (["PAdES-BASELINE-LTA", "PAdES-BASELINE-LT"], "PAdES-BASELINE-LT"),
        (["PAdES-BASELINE-LT", "PAdES-BASELINE-LTA"], "PAdES-BASELINE-LT"),
        (["PAdES-BASELINE-LTA", "PAdES-BASELINE-B", "PAdES-BASELINE-T"], "PAdES-BASELINE-B"),
        (["PAdES-BASELINE-LTA", "PDF-NOT-ETSI"], "PDF-NOT-ETSI"),
        (["XAdES-BASELINE-LTA", "XAdES-BASELINE-LTA"], "XAdES-BASELINE-LTA"),
        (["PAdES-BASELINE-T", "XAdES-BASELINE-T"], "PAdES-BASELINE-T"),
        (["PAdES-BASELINE-LTA", None], "PAdES-BASELINE-LTA"),
    ],
)
def test_with_several_signatures_the_weakest_format_is_reported(ext, formats, expected):
    report = _validation(*[_signature(fmt) for fmt in formats])

    assert ext.extract_signature_format(report) == expected


@pytest.mark.parametrize("report", [None, {}, [], "x", {"SimpleReport": "x"}, {"SimpleReport": {}}])
def test_extract_signature_format_tolerates_malformed_reports(ext, report):
    assert ext.extract_signature_format(report) is None


def test_the_extractor_reads_the_same_report_shapes_as_the_period(ext):
    one = {"signatureOrTimestamp": {"Signature": {"SignatureFormat": "CAdES-BASELINE-LTA"}}}

    assert ext.extract_signature_format({"simpleReport": one}) == "CAdES-BASELINE-LTA"


def test_a_value_that_is_not_a_short_string_is_ignored(ext):
    assert ext.extract_signature_format(_validation(_signature("X" * 200))) is None


def test_a_timestamp_renewal_never_sends_the_format(ext, monkeypatch, tmp_path):
    # Even if the validation response carried a Signature with a format, the renewal path does not ask for it.
    validation = _validation(_signature("PAdES-BASELINE-LTA"))

    event, requests_made, _ = _run(ext, monkeypatch, tmp_path, validation, timestamp_form="PDF")

    assert requests_made[0][0].endswith("/timestampDocument")
    assert "signatureFormat" not in event
    assert event["extensionPeriodMax"]


def test_the_failure_event_has_no_format(ext):
    captured = {}

    def fake_post(url, payload, *args, **kwargs):
        captured.update(payload)
        return _http({})

    with (
        mock.patch.object(ext, "_post_with_retry", side_effect=fake_post),
        mock.patch.object(ext, "_build_auth_headers", side_effect=lambda headers, logger: headers),
        mock.patch.object(ext, "_env_str", return_value=_EVENT_URL),
    ):
        assert ext.send_extension_event(doc_id="doc-id-894", error="boom", logger=logging.getLogger("t"))

    assert "signatureFormat" not in captured


def test_send_extension_event_sends_the_format_only_when_given(ext):
    sent = []

    def fake_post(url, payload, *args, **kwargs):
        sent.append(dict(payload))
        return _http({})

    with (
        mock.patch.object(ext, "_post_with_retry", side_effect=fake_post),
        mock.patch.object(ext, "_build_auth_headers", side_effect=lambda headers, logger: headers),
        mock.patch.object(ext, "_env_str", return_value=_EVENT_URL),
    ):
        ext.send_extension_event(doc_id="d", signature_format="XAdES-BASELINE-LTA", logger=logging.getLogger("t"))
        ext.send_extension_event(doc_id="d", signature_format=None, logger=logging.getLogger("t"))
        ext.send_extension_event(doc_id="d", signature_format="", logger=logging.getLogger("t"))

    assert sent[0]["signatureFormat"] == "XAdES-BASELINE-LTA"
    assert "signatureFormat" not in sent[1]
    assert "signatureFormat" not in sent[2]


def test_a_validation_failure_still_fails_the_extension_and_sends_no_event(ext, monkeypatch, tmp_path):
    # No SimpleReport and no certificates: the period cannot be determined, exactly as before this change.
    monkeypatch.setenv("IPDS_RE_PRESERVATION_SERVICE_URL", _EXTEND_URL)
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"original")

    def fake_post(url, payload, *args, **kwargs):
        if url == _EXTEND_URL:
            return _http({"bytes": base64.b64encode(b"x").decode("ascii")})
        return _http({})

    with (
        mock.patch.object(ext, "_build_auth_headers", side_effect=lambda headers, log: headers),
        mock.patch.object(ext, "_post_with_retry", side_effect=fake_post),
        mock.patch.object(ext, "timestamp_only_form", return_value=None),
        mock.patch.object(ext, "send_extension_event") as send,
    ):
        with pytest.raises(ext.IPDSExtensionError, match="could not extract ExtensionPeriodMax"):
            ext._extend_single_file(str(path), "doc-id-894", {}, 5, "SHA256", logging.getLogger("t"))

    send.assert_not_called()
