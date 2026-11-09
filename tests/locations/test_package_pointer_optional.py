"""Reingest and extraction must not depend on the pointer file being on disk.

The pointer file (``pointer.<uuid>.xml``) is recorded in the database but the
file may be missing from the SS internal location (e.g. it is not persistent).
"""

import contextlib
import logging
import os
import pathlib
import shutil
import tempfile
from unittest import mock

import pytest
from django.test import TestCase

from archivematica.storage_service.common import utils
from archivematica.storage_service.locations import models

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"
PACKAGE_MODULE = "archivematica.storage_service.locations.models.package"
COMPRESSED_AIP_UUID = "88deec53-c7dc-4828-865c-7356386e9399"
INTERNAL_SPACE_UUID = "7d20c992-bc92-4f92-a794-7161ff2cc08b"


# ------------------------------------------------------------------------------
# utils.get_compression_from_package_file
# ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header, name, expected",
    [
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "aip", utils.COMPRESSION_7Z_BZIP),
        (b"BZh91AY", "aip", utils.COMPRESSION_TAR_BZIP2),
        (b"\x1f\x8b\x08\x00", "aip", utils.COMPRESSION_TAR_GZIP),
        # The signature wins over a misleading extension.
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "aip.tar.gz", utils.COMPRESSION_7Z_BZIP),
        # Inconclusive signature: fall back to the extension.
        (b"????", "aip.7z", utils.COMPRESSION_7Z_BZIP),
        (b"????", "aip.tar.bz2", utils.COMPRESSION_TAR_BZIP2),
        (b"????", "aip.tar.gz", utils.COMPRESSION_TAR_GZIP),
        # Unknown: the caller falls back to unar.
        (b"PK\x03\x04", "aip.zip", None),
        (b"", "aip", None),
    ],
)
def test_get_compression_from_package_file(tmp_path, header, name, expected):
    package = tmp_path / name
    package.write_bytes(header)

    assert utils.get_compression_from_package_file(str(package)) == expected


def test_get_compression_from_package_file_uses_extension_if_unreadable(tmp_path):
    missing = tmp_path / "does-not-exist.7z"

    assert (
        utils.get_compression_from_package_file(str(missing))
        == utils.COMPRESSION_7Z_BZIP
    )
    assert (
        utils.get_compression_from_package_file(str(tmp_path / "does-not-exist")) is None
    )


# ------------------------------------------------------------------------------
# Package: extraction and pointer instance
# ------------------------------------------------------------------------------


class PointerOptionalTestCase(TestCase):
    fixture_files = ["base.json", "package.json"]
    fixtures = [FIXTURES_DIR / f for f in fixture_files]

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        # The SS internal location lives in a temporary directory.
        models.Space.objects.filter(uuid=INTERNAL_SPACE_UUID).update(path=self.tmp_dir)
        models.Location.objects.filter(
            purpose=models.Location.STORAGE_SERVICE_INTERNAL
        ).update(relative_path="ss")
        self.internal = models.Location.objects.get(
            purpose=models.Location.STORAGE_SERVICE_INTERNAL
        )
        os.makedirs(self.internal.full_path)
        self.package = models.Package.objects.get(uuid=COMPRESSED_AIP_UUID)
        self.package.pointer_file_location = self.internal
        self.package.pointer_file_path = os.path.join(
            "ab", f"pointer.{self.package.uuid}.xml"
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _create_pointer_file(self):
        path = self.package.full_pointer_file_path
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as f:
            f.write("<mets/>")
        return path


class TestExtractWithoutPointerFile(PointerOptionalTestCase):
    def _extract(self, package_file):
        """Run ``extract_file`` for ``package_file`` and return the command."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    models.Package, "fetch_local_path", return_value=package_file
                )
            )
            stack.enter_context(
                mock.patch.object(
                    models.Package, "get_base_directory", return_value="base"
                )
            )
            is_compressed = stack.enter_context(
                mock.patch.object(
                    models.Package, "is_compressed", new_callable=mock.PropertyMock
                )
            )
            check_output = stack.enter_context(
                mock.patch("subprocess.check_output", return_value=b"ok")
            )
            is_compressed.return_value = True
            self.package.extract_file(extract_path=self.tmp_dir)
        return check_output.call_args[0][0]

    def test_pointer_file_present_is_used(self):
        pointer = self._create_pointer_file()
        package_file = os.path.join(self.tmp_dir, "aip.7z")
        pathlib.Path(package_file).write_bytes(b"7z\xbc\xaf\x27\x1c")

        with mock.patch(
            f"{PACKAGE_MODULE}.utils.get_compression",
            return_value=utils.COMPRESSION_TAR_GZIP,
        ) as get_compression:
            command = self._extract(package_file)

        # The pointer file wins, even over the file signature.
        get_compression.assert_called_once_with(pointer)
        assert command[:2] == ["/bin/tar", "xvzf"]

    def test_pointer_file_missing_deduces_7z(self):
        package_file = os.path.join(self.tmp_dir, "aip.7z")
        pathlib.Path(package_file).write_bytes(b"7z\xbc\xaf\x27\x1c")
        assert not os.path.exists(self.package.full_pointer_file_path)

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
            command = self._extract(package_file)

        assert command[:2] == ["7z", "x"]
        assert command[-1] == package_file
        warning = "\n".join(logs.output)
        assert str(self.package.uuid) in warning
        assert self.package.full_pointer_file_path in warning

    def test_pointer_file_missing_deduces_tar_bz2(self):
        package_file = os.path.join(self.tmp_dir, "aip.tar.bz2")
        pathlib.Path(package_file).write_bytes(b"BZh91AY")

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING):
            command = self._extract(package_file)

        assert command[:2] == ["/bin/tar", "xvjf"]

    def test_pointer_file_missing_unknown_format_uses_unar(self):
        package_file = os.path.join(self.tmp_dir, "aip.zip")
        pathlib.Path(package_file).write_bytes(b"PK\x03\x04")

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING):
            command = self._extract(package_file)

        assert command[0] == "unar"

    def test_no_pointer_file_recorded_logs_and_deduces(self):
        self.package.pointer_file_location = None
        self.package.pointer_file_path = ""
        package_file = os.path.join(self.tmp_dir, "aip.7z")
        pathlib.Path(package_file).write_bytes(b"7z\xbc\xaf\x27\x1c")

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
            command = self._extract(package_file)

        assert command[:2] == ["7z", "x"]
        assert "has no pointer file" in "\n".join(logs.output)


class TestGetPointerInstance(PointerOptionalTestCase):
    def test_missing_pointer_file_returns_none_and_logs(self):
        with mock.patch.object(
            models.Package, "should_have_pointer_file", return_value=True
        ), mock.patch("metsrw.METSDocument.fromfile") as from_file:
            with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
                assert self.package.get_pointer_instance() is None

        from_file.assert_not_called()
        assert str(self.package.uuid) in "\n".join(logs.output)

    def test_existing_pointer_file_is_parsed(self):
        pointer = self._create_pointer_file()
        with mock.patch.object(
            models.Package, "should_have_pointer_file", return_value=True
        ), mock.patch("metsrw.METSDocument.fromfile") as from_file:
            assert self.package.get_pointer_instance() is from_file.return_value

        from_file.assert_called_once_with(pointer)


class TestProcessPointerFileForReingest(PointerOptionalTestCase):
    def test_compressed_to_uncompressed_tolerates_missing_pointer_file(self):
        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
            self.package._process_pointer_file_for_reingest(False, True, None, "/x")

        assert self.package.pointer_file_location is None
        assert self.package.pointer_file_path is None
        assert str(self.package.uuid) in "\n".join(logs.output)

    def test_compressed_to_uncompressed_removes_existing_pointer_file(self):
        pointer = self._create_pointer_file()

        self.package._process_pointer_file_for_reingest(False, True, None, "/x")

        assert not os.path.exists(pointer)
        assert self.package.pointer_file_location is None


class TestEnsurePointerFileLocation(PointerOptionalTestCase):
    def test_sets_defaults_when_missing(self):
        self.package.pointer_file_location = None
        self.package.pointer_file_path = None

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING):
            self.package._ensure_pointer_file_location()

        assert self.package.pointer_file_location == self.internal
        assert self.package.pointer_file_path == os.path.join(
            utils.uuid_to_path(self.package.uuid), f"pointer.{self.package.uuid}.xml"
        )

    def test_keeps_existing_values(self):
        before = (self.package.pointer_file_location, self.package.pointer_file_path)

        self.package._ensure_pointer_file_location()

        assert (
            self.package.pointer_file_location,
            self.package.pointer_file_path,
        ) == before


# ------------------------------------------------------------------------------
# finish_reingest: the pointer file is rebuilt when it is missing
# ------------------------------------------------------------------------------


class TestFinishReingestWithoutPointerFile(PointerOptionalTestCase):
    """``finish_reingest`` with everything but the pointer handling mocked."""

    def setUp(self):
        super().setUp()
        self.origin_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.origin_dir)
        self.origin_location = mock.Mock(
            full_path=self.origin_dir, relative_path="origin"
        )
        # Where AM leaves the pointer file of the reingested AIP.
        self.am_pointer_src = os.path.join(self.origin_dir, "pointer.xml")
        # Where ``_get_rein_pointer_paths`` expects it in the internal location
        # for an AIP that was compressed.
        self.rein_pointer_dst = os.path.join(
            self.internal.full_path, f"pointer.{self.package.uuid}.reingest.xml"
        )
        self.rein_aip = os.path.join(self.tmp_dir, "reingested.7z")
        pathlib.Path(self.rein_aip).write_bytes(b"x")

    def _finish_reingest(self, am_provides_pointer):
        if am_provides_pointer:
            pathlib.Path(self.am_pointer_src).write_text("<am-pointer/>")
            # What the (mocked) space move does.
            pathlib.Path(self.rein_pointer_dst).write_text("<am-pointer/>")
        package = self.package
        patches = {
            "_validate_pipelines_for_reingest": None,
            "extract_file": ("/old", "/old-tmp"),
            "_move_reingested_aip_from_origin_to_internal": self.rein_aip,
            "_overwrite_old_mets_with_rein_mets": None,
            "_compress_and_clean_for_reingest": ("/upd.7z", "/upd-parent"),
            "_move_rein_updated_to_final_dest": None,
            "create_replicas": None,
            "_process_pointer_file_for_reingest": None,
            "save": None,
            "run_post_store_callbacks": None,
            "_create_pointer_file_write_to_disk": None,
        }
        with mock.patch.multiple(
            models.Package,
            **{name: mock.DEFAULT for name in patches},
        ) as mocks, mock.patch.object(
            models.Package, "is_compressed", new_callable=mock.PropertyMock
        ) as is_compressed, mock.patch.multiple(
            PACKAGE_MODULE,
            _extract_rein_aip=mock.DEFAULT,
            _replace_old_metdata_with_reingested=mock.DEFAULT,
            _replace_old_pres_ders_with_reingested=mock.DEFAULT,
            _update_bag_payload_and_verify=mock.DEFAULT,
            _get_compression_details_from_premis_events=mock.DEFAULT,
        ) as module_mocks, mock.patch.object(
            models.Space, "move_from_storage_service"
        ), mock.patch(
            f"{PACKAGE_MODULE}.utils.recalculate_size", return_value=1
        ), mock.patch(
            f"{PACKAGE_MODULE}.utils.generate_checksum"
        ) as generate_checksum, mock.patch(
            f"{PACKAGE_MODULE}.utils.get_compression",
            return_value=utils.COMPRESSION_7Z_BZIP,
        ) as get_compression, mock.patch(
            f"{PACKAGE_MODULE}.shutil.rmtree"
        ):
            is_compressed.return_value = True
            for name, value in patches.items():
                mocks[name].return_value = value
            module_mocks["_extract_rein_aip"].return_value = "/rein"
            module_mocks["_replace_old_pres_ders_with_reingested"].return_value = []
            module_mocks["_get_compression_details_from_premis_events"].return_value = (
                "bzip2",
                "version",
                "tool",
            )
            generate_checksum.return_value.hexdigest.return_value = "abc"
            package.finish_reingest(
                self.origin_location,
                "origin-aip/aip.7z",
                self.internal,
                "reingest/aip.7z",
                premis_events=[],
            )
        # ``origin_path``'s directory decides where AM's pointer is looked for.
        return mocks, get_compression

    def _set_origin_dir_layout(self):
        # AM's pointer is looked up at dirname(origin_path)/pointer.xml
        os.makedirs(os.path.join(self.origin_dir, "origin-aip"))
        self.am_pointer_src = os.path.join(self.origin_dir, "origin-aip", "pointer.xml")

    def setUp_missing(self):
        self._set_origin_dir_layout()
        assert not os.path.exists(self.package.full_pointer_file_path)

    def test_missing_pointer_and_no_am_pointer_rebuilds_it(self):
        self.setUp_missing()

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
            mocks, _ = self._finish_reingest(am_provides_pointer=False)

        create = mocks["_create_pointer_file_write_to_disk"]
        create.assert_called_once()
        assert create.call_args[0][0] == self.package.full_pointer_file_path
        assert "rebuilding the missing pointer file" in "\n".join(logs.output)

    def test_missing_pointer_with_am_pointer_installs_it(self):
        self.setUp_missing()

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING) as logs:
            mocks, get_compression = self._finish_reingest(am_provides_pointer=True)

        mocks["_create_pointer_file_write_to_disk"].assert_not_called()
        installed = self.package.full_pointer_file_path
        assert pathlib.Path(installed).read_text() == "<am-pointer/>"
        # The AM pointer is moved, not left behind in the processing area.
        assert not os.path.exists(self.rein_pointer_dst)
        get_compression.assert_called_once_with(self.rein_pointer_dst)
        assert "installing the pointer file created by AM" in "\n".join(logs.output)

    def test_no_pointer_recorded_gets_default_location(self):
        self.setUp_missing()
        self.package.pointer_file_location = None
        self.package.pointer_file_path = ""

        with self.assertLogs(PACKAGE_MODULE, level=logging.WARNING):
            mocks, _ = self._finish_reingest(am_provides_pointer=False)

        create = mocks["_create_pointer_file_write_to_disk"]
        expected = os.path.join(
            self.internal.full_path,
            utils.uuid_to_path(self.package.uuid),
            f"pointer.{self.package.uuid}.xml",
        )
        assert create.call_args[0][0] == expected

    def test_existing_pointer_is_untouched_and_am_pointer_discarded(self):
        """Behaviour with a pointer file on disk does not change."""
        self._set_origin_dir_layout()
        pointer = self._create_pointer_file()

        mocks, _ = self._finish_reingest(am_provides_pointer=True)

        mocks["_create_pointer_file_write_to_disk"].assert_not_called()
        assert pathlib.Path(pointer).read_text() == "<mets/>"
        assert not os.path.exists(self.rein_pointer_dst)

    def test_existing_pointer_without_am_pointer_is_recreated(self):
        """Behaviour with a pointer file on disk does not change."""
        self._set_origin_dir_layout()
        self._create_pointer_file()

        mocks, _ = self._finish_reingest(am_provides_pointer=False)

        mocks["_create_pointer_file_write_to_disk"].assert_called_once()
