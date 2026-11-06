"""IPDS-831: a failed signature extension is reported to IPDS with its message.

IPDS-853: an object that carries only RFC 3161 timestamps is renewed with timestampDocument, and the DSS result is
checked before it replaces the stored file.

The module is loaded by path: it needs only the standard library and ``requests``, and importing it through its
package would start the Django models.
"""

import base64
import datetime
import hashlib
import importlib.util
import io
import logging
import pathlib
import zipfile
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


@pytest.fixture(scope="module")
def ext():
    spec = importlib.util.spec_from_file_location("ipds_extension_under_test", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failure_is_reported_to_ipds_with_the_message_and_reraised(ext, tmp_path):
    with mock.patch.object(ext, "send_extension_event", return_value=True) as send:
        with pytest.raises(ext.IPDSExtensionError, match="objects directory not found"):
            ext.extend_aip_objects(str(tmp_path / "missing"), "doc.pdf", "doc-id-1", logger=logging.getLogger("t"))

    send.assert_called_once()
    kwargs = send.call_args.kwargs
    assert kwargs["doc_id"] == "doc-id-1"
    assert "objects directory not found" in kwargs["error"]
    assert kwargs.get("period_dt") is None
    assert kwargs.get("hash_value") is None


def test_original_error_survives_when_the_report_itself_fails(ext, tmp_path):
    with mock.patch.object(ext, "send_extension_event", side_effect=RuntimeError("ipds unreachable")):
        with pytest.raises(ext.IPDSExtensionError, match="objects directory not found"):
            ext.extend_aip_objects(str(tmp_path / "missing"), "", "doc-id-2", logger=logging.getLogger("t"))


def test_success_sends_no_failure_event(ext, tmp_path):
    with mock.patch.object(ext, "_extend_aip_objects", return_value={"a": ("h", "sha256")}) as impl, mock.patch.object(
        ext, "send_extension_event"
    ) as send:
        result = ext.extend_aip_objects(str(tmp_path), "doc.pdf", "doc-id-3", logger=logging.getLogger("t"))

    assert result == {"a": ("h", "sha256")}
    impl.assert_called_once()
    send.assert_not_called()


def test_the_failure_event_payload_carries_the_error_and_no_success_fields(ext):
    captured = {}

    def fake_post(url, payload, *args, **kwargs):
        captured.update(payload)
        response = mock.Mock()
        response.status_code = 200
        return response

    with mock.patch.object(ext, "_post_with_retry", side_effect=fake_post), mock.patch.object(
        ext, "_build_auth_headers", side_effect=lambda headers, logger: headers
    ), mock.patch.object(ext, "_env_str", return_value="https://ipds.example.invalid/event"):
        assert ext.send_extension_event(doc_id="doc-id-4", error="x" * 900, logger=logging.getLogger("t"))

    assert captured["ipdsDocId"] == "doc-id-4"
    assert len(captured["error"]) == 500
    assert "extensionPeriodMax" not in captured
    assert "hash" not in captured
    assert "fileSize" not in captured


# ---------------------------------------------------------------------------
# IPDS-853: objects that carry only RFC 3161 timestamps
# ---------------------------------------------------------------------------

_TIMESTAMP = b"ETSI.RFC3161"
_SIGNATURE = b"adbe.pkcs7.detached"
_PLACEHOLDER = b"/ByteRange [0 0000000000 0000000000 0000000000]"
_ASICS = "application/vnd.etsi.asic-s+zip"
_ASICE = "application/vnd.etsi.asic-e+zip"
_EXTEND_URL = "https://dss.example.invalid/dss/services/rest/signature/one-document/extendDocument"


def _signature_object(number, subfilter):
    kind = b"DocTimeStamp" if subfilter == _TIMESTAMP else b"Sig"
    entry = b" /SubFilter /" + subfilter if subfilter else b""
    return (
        b"%d 0 obj\n<< /Type /%s /Filter /Adobe.PPKLite%s " % (number, kind, entry)
        + _PLACEHOLDER
        + b" /Contents <" + b"0" * 64 + b"> >>\nendobj\n"
    )


def _fill_byte_ranges(data):
    """Give every placeholder /ByteRange the values that leave out exactly its own /Contents."""
    out = bytearray(data)
    pos = out.find(_PLACEHOLDER)
    while pos >= 0:
        contents_start = out.index(b"<", pos)
        contents_end = out.index(b">", contents_start) + 1
        out[pos:pos + len(_PLACEHOLDER)] = b"/ByteRange [0 %010d %010d %010d]" % (
            contents_start, contents_end, len(out) - contents_end
        )
        pos = out.find(_PLACEHOLDER, pos)
    return bytes(out)


def _pdf(*subfilters):
    """A small PDF with one signature dictionary per SubFilter (``None``: a dictionary without SubFilter)."""
    body = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    for number, subfilter in enumerate(subfilters, start=2):
        body += _signature_object(number, subfilter)
    return _fill_byte_ranges(body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")


def _pdf_incremental(previous, subfilter):
    """*previous* plus an incremental revision that adds one signature dictionary."""
    revision = _signature_object(90, subfilter) + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    return _fill_byte_ranges(previous + revision)


def _der(tag, content):
    size = len(content)
    if size < 0x80:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _token(tst_info, version=3, unsigned_extra=b""):
    """A structurally valid RFC 3161 token: ContentInfo(signedData) over id-ct-TSTInfo carrying *tst_info*."""
    encapsulated = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d0109100104")) + _der(0xA0, _der(0x04, tst_info)))
    signed_data = _der(0x30, _der(0x02, bytes([version])) + _der(0x31, b"") + encapsulated + unsigned_extra)
    return _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010702")) + _der(0xA0, signed_data))


_TST_1 = _der(0x30, b"tst-info-initial")
_TST_2 = _der(0x30, b"tst-info-renewal")
_TOKEN = {"META-INF/timestamp.tst": _token(_TST_1)}


def _zip(entries, mimetype=_ASICS, stored=()):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        if mimetype is not None:
            zf.writestr(zipfile.ZipInfo("mimetype"), mimetype, compress_type=zipfile.ZIP_STORED)
        for name, data in entries.items():
            zf.writestr(name, data, compress_type=zipfile.ZIP_STORED if name in stored else zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


def _asic_only_timestamp(mimetype=_ASICS, document=b"document 853"):
    return _zip({"doc.txt": document, "META-INF/timestamp.tst": _token(_TST_1)}, mimetype=mimetype)


def _asic_renewed(original_token=None, document=b"document 853", mimetype=_ASICS, new_token=True):
    entries = {
        "doc.txt": document,
        # DSS rewrites the initial token (SignedData v3 -> v5 with validation data); its TSTInfo stays the same
        "META-INF/timestamp.tst": original_token or _token(_TST_1, version=5, unsigned_extra=_der(0xA1, b"ocsp")),
        "META-INF/ASiCArchiveManifest.xml": b"<ASiCManifest/>",
    }
    if new_token:
        entries["META-INF/timestamp002.tst"] = _token(_TST_2)
    return _zip(entries, mimetype=mimetype)


@pytest.mark.parametrize(
    "data, file_name, expected",
    [
        (_pdf(_TIMESTAMP), "doc.pdf", "PDF"),
        (_pdf(_TIMESTAMP, _TIMESTAMP), "doc.pdf", "PDF"),
        (_pdf(_TIMESTAMP), "doc.bin", "PDF"),
        (_pdf(b"adbe.pkcs7.detached"), "doc.pdf", None),
        (_pdf(b"ETSI.CAdES.detached", _TIMESTAMP), "doc.pdf", None),
        (_pdf(_TIMESTAMP, b"adbe.pkcs7.sha1"), "doc.pdf", None),
        (_pdf(b"adbe.x509.rsa_sha1"), "doc.pdf", None),
        (_pdf(), "doc.pdf", None),
        (_pdf(None), "doc.pdf", None),
        (_pdf(_TIMESTAMP).replace(b"/ByteRange [0 ", b"/ByteRange [7 ", 1), "doc.pdf", None),
        (_asic_only_timestamp(), "doc.asics", "ASiC_S"),
        (_asic_only_timestamp(), "doc.scs", "ASiC_S"),
        (_asic_only_timestamp(_ASICE), "doc.asice", "ASiC_E"),
        (_asic_only_timestamp(_ASICE), "doc.zip", "ASiC_E"),
        (_asic_only_timestamp(mimetype=None), "doc.asics", "ASiC_S"),
        (_asic_only_timestamp(mimetype=None), "doc.zip", None),
        (_asic_only_timestamp(_ASICE), "doc.asics", None),
        (_asic_only_timestamp("application/zip"), "doc.asics", None),
        (_zip({"doc.pdf": _pdf(), **_TOKEN}, stored=("doc.pdf",)), "doc.asics", "ASiC_S"),
        (_zip({"doc.txt": b"x", "META-INF/signature.p7s": b"cms", **_TOKEN}), "doc.asics", None),
        (_zip({"doc.txt": b"x", "META-INF/signatures001.xml": b"<x/>", **_TOKEN}, _ASICE), "doc.asice", None),
        (_zip({"doc.txt": b"x", "META-INF/evidencerecord.ers": b"er", **_TOKEN}), "doc.asics", None),
        (_zip({"doc.txt": b"x"}), "doc.asics", None),
        (_zip({"doc.txt": b"x", "META-INF/timestamp.tst": b"not a token"}), "doc.asics", None),
        (_zip({"a.txt": b"a", "b.txt": b"b", **_TOKEN}), "doc.asics", None),
        (_zip(_TOKEN), "doc.asics", None),
        (_token(_TST_1), "doc.tst", None),
        (b'<?xml version="1.0"?><d>853</d>', "doc.xml", None),
        (b'{"d": "853"}', "doc.json", None),
        (b"PK\x03\x04 truncated", "doc.asics", None),
    ],
    ids=[
        "pdf-one-doc-timestamp",
        "pdf-two-doc-timestamps",
        "pdf-content-wins-over-extension",
        "pdf-signature",
        "pdf-pades-lta",
        "pdf-timestamp-and-signature",
        "pdf-x509-signature",
        "pdf-unsigned",
        "pdf-dictionary-without-subfilter",
        "pdf-byte-range-not-of-this-file",
        "asics-timestamp-only",
        "scs-timestamp-only",
        "asice-timestamp-only",
        "zip-name-asice-mimetype",
        "asics-without-mimetype",
        "zip-without-mimetype",
        "extension-and-mimetype-disagree",
        "not-an-asic-mimetype",
        "asics-with-stored-pdf-document",
        "asic-with-cades-signature",
        "asic-with-xades-signature",
        "asic-with-evidence-record",
        "asic-without-timestamp",
        "asic-with-a-tst-that-is-not-a-token",
        "asics-with-two-documents",
        "asic-without-signed-data",
        "loose-timestamp-token",
        "xml",
        "json",
        "broken-zip",
    ],
)
def test_timestamp_only_detection(ext, data, file_name, expected):
    assert ext.timestamp_only_form(data, file_name) == expected


def _response(data):
    response = mock.Mock()
    response.status_code = 200
    response.json.return_value = {"bytes": base64.b64encode(data).decode("ascii"), "name": "ignored"}
    return response


def _run_extension(ext, monkeypatch, tmp_path, file_name, original, dss_result, url=_EXTEND_URL):
    """Run _extend_single_file with the DSS, the validation and the IPDS event mocked; return what was called."""
    monkeypatch.setenv("IPDS_RE_PRESERVATION_SERVICE_URL", url)
    path = tmp_path / file_name
    path.write_bytes(original)
    period = datetime.datetime(2036, 4, 26, 10, 57, 8, tzinfo=datetime.timezone.utc)
    with (
        mock.patch.object(ext, "_build_auth_headers", side_effect=lambda headers, logger: headers),
        mock.patch.object(ext, "_post_with_retry", return_value=_response(dss_result)) as post,
        mock.patch.object(ext, "validate_signature_and_extract_period", return_value=period) as validate,
        mock.patch.object(ext, "send_extension_event", return_value=True) as send,
    ):
        calls = {"post": post, "validate": validate, "send": send, "path": path}
        try:
            calls["result"] = ext._extend_single_file(
                file_path=str(path),
                ipds_doc_id="doc-id-853",
                headers={},
                timeout=5,
                configured_digest="SHA256",
                logger=logging.getLogger("t"),
            )
        except ext.IPDSExtensionError as exc:
            calls["error"] = exc
    return calls


def test_a_timestamp_only_pdf_is_renewed_with_timestamp_document(ext, monkeypatch, tmp_path):
    original = _pdf(_TIMESTAMP)
    renewed = _pdf_incremental(original, _TIMESTAMP)

    calls = _run_extension(ext, monkeypatch, tmp_path, "doc.pdf", original, renewed)

    assert "error" not in calls
    url, payload = calls["post"].call_args.args[:2]
    assert url.endswith("/signature/one-document/timestampDocument")
    assert payload == {
        "toTimestampDocument": {"bytes": base64.b64encode(original).decode("ascii"), "name": "doc.pdf"},
        "timestampParameters": {"timestampContainerForm": "PDF", "digestAlgorithm": "SHA256"},
    }
    assert calls["path"].read_bytes() == renewed
    assert calls["validate"].call_args.kwargs["latest_timestamp"] is True
    assert calls["send"].call_args.kwargs["hash_value"] == hashlib.sha256(renewed).hexdigest()
    assert calls["send"].call_args.kwargs["file_size"] == len(renewed)
    assert calls["result"] == (hashlib.sha256(renewed).hexdigest(), "sha256")


@pytest.mark.parametrize(
    "file_name, mimetype, form", [("doc.asics", _ASICS, "ASiC_S"), ("doc.asice", _ASICE, "ASiC_E")]
)
def test_a_timestamp_only_asic_is_renewed_with_its_container_form(
    ext, monkeypatch, tmp_path, file_name, mimetype, form
):
    original = _asic_only_timestamp(mimetype)
    renewed = _asic_renewed(mimetype=mimetype)

    calls = _run_extension(ext, monkeypatch, tmp_path, file_name, original, renewed)

    assert "error" not in calls
    url, payload = calls["post"].call_args.args[:2]
    assert url.endswith("/timestampDocument")
    assert payload["timestampParameters"] == {"timestampContainerForm": form, "digestAlgorithm": "SHA256"}
    assert calls["path"].read_bytes() == renewed
    calls["send"].assert_called_once()


def test_a_signed_pdf_keeps_extend_document(ext, monkeypatch, tmp_path):
    original = _pdf(b"ETSI.CAdES.detached", _TIMESTAMP)
    extended = _pdf_incremental(original, _TIMESTAMP)

    calls = _run_extension(ext, monkeypatch, tmp_path, "doc.pdf", original, extended)

    assert "error" not in calls
    url, payload = calls["post"].call_args.args[:2]
    assert url == _EXTEND_URL
    assert payload == {
        "toExtendDocument": {"bytes": base64.b64encode(original).decode("ascii"), "name": "doc.pdf"},
        "parameters": {"signatureLevel": "PAdES_BASELINE_LTA"},
    }
    assert calls["validate"].call_args.kwargs["latest_timestamp"] is False
    assert calls["path"].read_bytes() == extended


def test_a_signed_asic_keeps_extend_document(ext, monkeypatch, tmp_path):
    original = _zip({"doc.txt": b"x", "META-INF/signature.p7s": b"cms"})

    calls = _run_extension(ext, monkeypatch, tmp_path, "doc.asics", original, original + b"extended")

    url, payload = calls["post"].call_args.args[:2]
    assert url == _EXTEND_URL
    assert payload["parameters"] == {"signatureLevel": "CAdES_BASELINE_LTA"}


def test_the_timestamp_url_must_be_derivable(ext, monkeypatch, tmp_path):
    calls = _run_extension(
        ext, monkeypatch, tmp_path, "doc.pdf", _pdf(_TIMESTAMP), b"", url="https://dss.example.invalid/custom"
    )

    assert "timestampDocument URL cannot be derived" in str(calls["error"])
    calls["post"].assert_not_called()


@pytest.mark.parametrize(
    "file_name, original, dss_result, message",
    [
        ("doc.pdf", _pdf(_TIMESTAMP), _pdf_incremental(_pdf(_SIGNATURE), _TIMESTAMP), "not an exact prefix"),
        ("doc.pdf", _pdf(_TIMESTAMP), _pdf(_TIMESTAMP), "not an exact prefix"),
        ("doc.pdf", _pdf(_TIMESTAMP), _pdf(_TIMESTAMP) + b"\n% no new revision\n", "does not add a document"),
        ("doc.pdf", _pdf(_TIMESTAMP), _pdf_incremental(_pdf(_TIMESTAMP), _SIGNATURE), "does not add a document"),
        ("doc.asics", _asic_only_timestamp(), _asic_renewed(document=b"altered"), "signed data inside the container"),
        ("doc.asics", _asic_only_timestamp(), _asic_renewed(original_token=_token(_TST_2)), "original timestamp"),
        ("doc.asics", _asic_only_timestamp(), _asic_renewed(new_token=False), "does not add a timestamp token"),
        ("doc.asics", _asic_only_timestamp(), _asic_renewed(mimetype=_ASICE), "mimetype"),
        ("doc.asics", _asic_only_timestamp(), b"not a zip at all", "not a valid ZIP"),
    ],
    ids=[
        "pdf-other-document",
        "pdf-unchanged",
        "pdf-without-new-timestamp",
        "pdf-adds-a-signature",
        "asic-altered-document",
        "asic-initial-timestamp-replaced",
        "asic-without-new-timestamp",
        "asic-wrong-mimetype",
        "asic-not-a-zip",
    ],
)
def test_a_renewal_that_alters_the_object_is_rejected_before_writing(
    ext, monkeypatch, tmp_path, file_name, original, dss_result, message
):
    calls = _run_extension(ext, monkeypatch, tmp_path, file_name, original, dss_result)

    assert message in str(calls["error"])
    assert "rejected before writing" in str(calls["error"])
    assert calls["path"].read_bytes() == original
    assert [p.name for p in tmp_path.iterdir()] == [file_name]
    calls["validate"].assert_not_called()
    calls["send"].assert_not_called()


def _validation(*entries):
    return {"SimpleReport": {"signatureOrTimestampOrEvidenceRecord": list(entries)}}


def _timestamp_entry(produced, period):
    return {"Timestamp": {"ProductionTime": produced, "ExtensionPeriodMax": period}}


def test_the_renewal_date_comes_from_the_most_recent_timestamp(ext):
    report = _validation(
        _timestamp_entry("2026-11-05T11:31:39Z", "2030-01-01T00:00:00Z"),  # initial timestamp, older TSU certificate
        _timestamp_entry("2026-11-06T08:00:00Z", "2036-04-26T10:57:08Z"),  # renewal timestamp
    )

    latest = ext.extract_extension_period_max(report, latest_timestamp=True)
    earliest = ext.extract_extension_period_max(report)

    assert latest == datetime.datetime(2036, 4, 26, 10, 57, 8, tzinfo=datetime.timezone.utc)
    assert earliest == datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)


def test_the_most_recent_timestamp_rule_falls_back_without_dated_timestamps(ext):
    report = _validation({"Signature": {"ExtensionPeriodMax": "2031-01-01T00:00:00Z"}})

    assert ext.extract_extension_period_max(report, latest_timestamp=True) == datetime.datetime(
        2031, 1, 1, tzinfo=datetime.timezone.utc
    )
