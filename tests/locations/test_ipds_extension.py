"""IPDS-831: a failed signature extension is reported to IPDS with its message.

The module is loaded by path: it needs only the standard library and ``requests``, and importing it through its
package would start the Django models.
"""

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
