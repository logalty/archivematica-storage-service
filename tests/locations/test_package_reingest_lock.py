"""The reingest lock (``misc_attributes["reingest_pipeline"]``) must not stay
set when the reingest never started."""

import pathlib
from unittest import mock

import requests
from django.test import TestCase

from archivematica.storage_service.locations import models

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"
AIP_UUID = "88deec53-c7dc-4828-865c-7356386e9399"
PIPELINE_UUID = "b25f6b71-3ebf-4fd9-8c0d-6ba58d0d2e01"
OTHER_PIPELINE_UUID = "0c1d6bd0-8a06-4d3f-a2f4-0a1a6d1b3f6c"


def _reload_misc_attributes():
    return models.Package.objects.get(uuid=AIP_UUID).misc_attributes


class TestStartReingestLock(TestCase):
    fixture_files = ["base.json", "package.json"]
    fixtures = [FIXTURES_DIR / f for f in fixture_files]

    def setUp(self):
        self.package = models.Package.objects.get(uuid=AIP_UUID)
        self.pipeline = mock.Mock(uuid=PIPELINE_UUID)

    def _start(self, **kwargs):
        return self.package.start_reingest(self.pipeline, "full", **kwargs)

    def test_failed_integrity_check_releases_the_lock(self):
        with mock.patch.object(
            models.Package,
            "check_fixity",
            return_value=(False, [], "fixity failed", None),
        ):
            response = self._start()

        assert response["error"] is True
        assert response["status_code"] == 500
        # Released in memory and in the database.
        assert "reingest_pipeline" not in self.package.misc_attributes
        assert "reingest_pipeline" not in _reload_misc_attributes()

    def test_lock_is_held_while_the_reingest_runs(self):
        seen = {}

        def fixity(*args, **kwargs):
            seen["in_db"] = _reload_misc_attributes().get("reingest_pipeline")
            return (False, [], "fixity failed", None)

        with mock.patch.object(models.Package, "check_fixity", side_effect=fixity):
            self._start()

        # Concurrent requests still see the lock until the outcome is known.
        assert seen["in_db"] == PIPELINE_UUID

    def test_exception_releases_the_lock_and_propagates(self):
        with mock.patch.object(
            models.Package, "check_fixity", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(RuntimeError):
                self._start()

        assert "reingest_pipeline" not in _reload_misc_attributes()

    def test_pipeline_error_releases_the_lock(self):
        error = {"error": True, "status_code": 502, "message": "bad gateway"}
        with mock.patch.object(
            models.Package, "_start_reingest_locked", return_value=error
        ):
            assert self._start() == error

        assert "reingest_pipeline" not in _reload_misc_attributes()

    def test_successful_start_keeps_the_lock(self):
        ok = {"error": False, "status_code": 202, "message": "ok"}
        with mock.patch.object(
            models.Package, "_start_reingest_locked", return_value=ok
        ):
            assert self._start() == ok

        assert _reload_misc_attributes()["reingest_pipeline"] == PIPELINE_UUID

    def test_concurrent_reingest_is_rejected_and_keeps_the_first_lock(self):
        self.package.misc_attributes = {"reingest_pipeline": OTHER_PIPELINE_UUID}
        self.package.save()

        with mock.patch.object(models.Package, "check_fixity") as check_fixity:
            response = self._start()

        assert response["status_code"] == 409
        check_fixity.assert_not_called()
        # The running reingest must not lose its lock because of this request.
        assert _reload_misc_attributes()["reingest_pipeline"] == OTHER_PIPELINE_UUID

    def test_failed_ipds_represervation_restores_previous_state(self):
        self.package.misc_attributes = {"reingest_pipeline": OTHER_PIPELINE_UUID}
        self.package.save()

        with mock.patch.object(
            models.Package,
            "check_fixity",
            return_value=(False, [], "fixity failed", None),
        ):
            response = self._start(
                reingest_ipds_represervation="true",
                reingest_ipds_doc_name="doc.pdf",
                reingest_ipds_doc_id="123",
            )

        assert response["status_code"] == 500
        assert _reload_misc_attributes() == {"reingest_pipeline": OTHER_PIPELINE_UUID}

    def test_request_exception_from_pipeline_releases_the_lock(self):
        with mock.patch.object(
            models.Package,
            "_start_reingest_locked",
            side_effect=requests.exceptions.ConnectionError("down"),
        ):
            with self.assertRaises(requests.exceptions.ConnectionError):
                self._start()

        assert "reingest_pipeline" not in _reload_misc_attributes()
