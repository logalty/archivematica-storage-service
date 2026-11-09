"""Clearing the reingest lock through the API must persist."""

import base64
import json
import pathlib

from django.contrib.auth.models import User
from django.test import TestCase

from archivematica.storage_service.locations import models

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"
AIP_UUID = "88deec53-c7dc-4828-865c-7356386e9399"
PIPELINE_UUID = "b25f6b71-3ebf-4fd9-8c0d-6ba58d0d2e01"


class TestPatchReingestClearsLock(TestCase):
    """``PATCH /api/v2/file/<uuid>/ {"reingest": null}`` must persist."""

    fixture_files = ["base.json", "package.json"]
    fixtures = [FIXTURES_DIR / f for f in fixture_files]

    def setUp(self):
        user = User.objects.get(username="test")
        user.set_password("test")
        self.client.defaults["HTTP_AUTHORIZATION"] = "Basic " + base64.b64encode(
            b"test:test"
        ).decode("utf8")
        package = models.Package.objects.get(uuid=AIP_UUID)
        # Packages stored through AM always have an origin pipeline.
        package.origin_pipeline = models.Pipeline.objects.get(
            uuid="0cbf947a-1b19-4a01-a575-454078768fcd"
        )
        package.misc_attributes = {
            "reingest_pipeline": PIPELINE_UUID,
            "other": "kept",
        }
        package.save()

    def _patch(self, body):
        return self.client.patch(
            f"/api/v2/file/{AIP_UUID}/",
            data=json.dumps(body),
            content_type="application/json",
        )

    def test_patch_reingest_persists_the_cleared_lock(self):
        response = self._patch({"reingest": None})

        assert response.status_code == 202, response.content
        misc = models.Package.objects.get(uuid=AIP_UUID).misc_attributes
        assert misc["reingest_pipeline"] is None
        # Other attributes are untouched.
        assert misc["other"] == "kept"
