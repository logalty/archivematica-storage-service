import os
import logging
import traceback
import requests
import boto3
import botocore
import re
import py7zr
import tempfile

from django.db import models
from .location import Location
from django.utils.translation import gettext_lazy as _

LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 30
READ_TIMEOUT = 600
DELETE_TIMEOUT = 60


class LogaltyRESTException(Exception):
    def __init__(self, msg, url=None, exc_info=False):
        parts = [msg]
        if url:
            parts.append(f" URL={url}")
        if exc_info:
            parts.append(traceback.format_exc())
        super().__init__("".join(parts))


class Logalty(models.Model):
    space = models.OneToOneField("Space", to_field="uuid", on_delete=models.CASCADE)

    logalty_user = models.CharField(max_length=64, blank=True,verbose_name="The username for Logalty Storage Service")
    logalty_pass = models.CharField(max_length=256, blank=True,verbose_name="The password for Logalty Storage Service")
    logalty_url = models.CharField(max_length=2048,verbose_name="The url for Logalty Storage Service")

    s3_access_key_id = models.CharField(max_length=64, blank=True,verbose_name="The USER_ID for AWS S3 on which upload the files before encryption")
    s3_secret_access_key = models.CharField(max_length=256, blank=True,verbose_name="The SECRET for AWS S3 on which upload the files before encryption")
    s3_endpoint_url = models.CharField(max_length=2048,verbose_name="The URL for AWS S3 on which upload the files before encryption")
    s3_region = models.CharField(max_length=64,verbose_name="The REGION for AWS S3 on which upload the files before encryption")
    s3_bucket = models.CharField(max_length=64, blank=True,verbose_name="The s3 BUCKET for AWS S3 on which upload the files before encryption")

    class Meta:
        app_label = "locations"
        verbose_name = "Logalty Storage"

    ALLOWED_LOCATION_PURPOSE = [
        Location.AIP_STORAGE,
        Location.DIP_STORAGE,
    ]

    # -----------------------
    # S3 CLIENT
    # -----------------------
    @property
    def s3(self):
        if not hasattr(self, "_s3"):
            self._s3 = boto3.resource(
                "s3",
                region_name=self.s3_region,
                endpoint_url=self.s3_endpoint_url,
                aws_access_key_id=self.s3_access_key_id,
                aws_secret_access_key=self.s3_secret_access_key,
            )
        return self._s3

    @property
    def bucket(self):
        return self.s3.Bucket(self.s3_bucket)

    def browse(self, path):
        """Browse a path in the storage."""
        LOGGER.info("📁 [BROWSE] Path: %s", path)
        pass

    def _get_storage_prefix(self, is_dip: bool):
        return "ipds/dip_storage" if is_dip else "ipds/aip_storage"
    # -----------------------
    # UUID PARSER
    # -----------------------
    def _extract_package_uuid(self, path):
        match = re.search(
            r"/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/"
            r"([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/",
            path,
            re.IGNORECASE,
        )

        if not match:
            return None

        g = match.groups()

        return (
            f"{g[0]}{g[1]}-"
            f"{g[2]}-"
            f"{g[3]}-"
            f"{g[4]}-"
            f"{g[5]}{g[6]}{g[7]}"
        )

    # -----------------------
    # ENSURE BUCKET EXISTS
    # -----------------------
    def _ensure_bucket_exists(self):
        try:
            LOGGER.info("🗑️ [_ensure_bucket_exists] Checking bucket existence: %s", self.s3_bucket)
            self.s3.meta.client.head_bucket(Bucket=self.s3_bucket)
            return
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")

            # real access error → do NOT auto-create
            if code in ("403", "AccessDenied"):
                raise

        try:
            if self.s3_region == "us-east-1":
                self.s3.create_bucket(Bucket=self.s3_bucket)
            else:
                self.s3.create_bucket(
                    Bucket=self.s3_bucket,
                    CreateBucketConfiguration={
                        "LocationConstraint": self.s3_region
                    },
                )
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in ("BucketAlreadyExists", "BucketAlreadyOwnedByYou"):
                raise

    # -----------------------
    # DELETE PATH
    # -----------------------
    def delete_path(self, delete_path):
        LOGGER.info("🗑️ [DELETE] Path: %s", delete_path)
        url = f"{self.logalty_url}/file"

        try:
            r = requests.delete(
                url,
                params={"destination": delete_path},
                auth=(self.logalty_user, self.logalty_pass),
                timeout=DELETE_TIMEOUT,
            )
            r.raise_for_status()

        except Exception as e:
            LOGGER.error("❌ Delete failed %s: %s", delete_path, e)
            raise LogaltyRESTException("Delete failed", url=url, exc_info=True)

    # -----------------------
    # UPLOAD + ENCRYPT (FIXED)
    # -----------------------
    def _upload_then_encrypt(self, file_path, s3_key, package=None, is_dip=False):

        self._ensure_bucket_exists()
        filename = os.path.basename(file_path)

        meta = {}
        user_id = None
        object_salt = None

        if package and getattr(package, "misc_attributes", None):
            user_id = package.misc_attributes.get("user_id")
            object_salt = package.misc_attributes.get("object_salt")

            if user_id is not None:
                meta["user_id"] = str(user_id)
            if object_salt is not None:
                meta["object_salt"] = str(object_salt)

        # ---------------- S3 UPLOAD SAFE ----------------
        try:
            with open(file_path, "rb") as f:
                upload_kwargs = {
                    "Fileobj": f,
                    "Key": s3_key,
                }

                if meta:
                    upload_kwargs["ExtraArgs"] = {"Metadata": meta}

                self.bucket.upload_fileobj(**upload_kwargs)
                LOGGER.info("✅✅ S3 upload completed OK: %s", s3_key)

        except Exception as e:
            LOGGER.error("❌ S3 upload failed: %s", e)
            raise LogaltyRESTException(f"S3 upload failed: {e}") from e

        # ---------------- SPRING BOOT CALL ----------------
        try:
            endpoint = "/file/dip" if is_dip else "/file/aip"
            url = f"{self.logalty_url}{endpoint}"

            payload = {
                "destination": s3_key,
                "filename": filename,
            }

            if user_id:
                payload["user_id"] = user_id
            if object_salt:
                payload["object_salt"] = object_salt

            LOGGER.info("📡 Calling IPDS Storage to encrypt AIP/DIP, url %s payload=%s", url, payload)

            r = requests.post(
                url,
                data=payload,
                auth=(self.logalty_user, self.logalty_pass),
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            r.raise_for_status()

            LOGGER.info("🔐 Encryption triggered with s3 key: %s", s3_key)
            return s3_key

        except Exception as e:
            LOGGER.error("❌ IPDS Failed to encrypt AIP/DIP → rollback S3: %s", e)
            try:
                self.bucket.Object(s3_key).delete()
                LOGGER.info("🗑️ Rollback OK: %s", s3_key)
            except Exception as del_err:
                LOGGER.error("❌ Rollback failed: %s", del_err)

            raise LogaltyRESTException(f"Encryption failed: {e}") from e

    # -----------------------
    # UPLOAD ENTRYPOINT
    # -----------------------
    def move_from_storage_service(self, source_path, destination_path, package=None):
        if package:
            is_dip = getattr(package, "package_type", None) == "DIP"
        else:
            is_dip = self._resolve_package_type(package, source_path) == "DIP"
        archive_path = None

        LOGGER.info(
            "⬆️ Upload requested source=%s destination=%s package_type=%s",
            source_path,
            destination_path,
            getattr(package, "package_type", None),
        )

        try:

            # AIP already packaged
            if (
                    not is_dip
                    and os.path.isfile(source_path)
                    and source_path.endswith(".7z")
            ):
                archive_path = source_path
                LOGGER.info(
                    "📦 AIP already packaged as 7z, uploading directly: %s",
                    source_path,
                )
            # DIRECTORY
            elif os.path.isdir(source_path):
                fd, archive_path = tempfile.mkstemp(suffix=".7z")
                os.close(fd)

                LOGGER.info("📦 Compressing directory %s", source_path)

                with py7zr.SevenZipFile(archive_path, "w") as archive:
                    archive.writeall(source_path, arcname=os.path.basename(source_path))

            # FILE
            elif os.path.isfile(source_path):
                fd, archive_path = tempfile.mkstemp(suffix=".7z")
                os.close(fd)

                LOGGER.info("📦 Compressing file %s", source_path)

                with py7zr.SevenZipFile(archive_path, "w") as archive:
                    archive.write(source_path, arcname=os.path.basename(source_path))

            else:
                raise ValueError(f"Invalid source path: {source_path}")
            LOGGER.info(
                "✅ Archive ready: %s (%s bytes)",
                archive_path,
                os.path.getsize(archive_path),
            )
            storage_prefix = self._get_storage_prefix(is_dip)
            clean_dest = destination_path.strip("/")

            s3_key = f"{storage_prefix}/{clean_dest}"

            LOGGER.info("☁️ Uploading to S3 key: %s", s3_key)

            self._upload_then_encrypt(
                archive_path,
                s3_key,
                package=package,
                is_dip=is_dip,
            )
            LOGGER.info(
                "✅ Upload and encryption completed successfully"
            )
        except Exception as exp:
            LOGGER.error("❌ Upload failed: %s", exp)
            if archive_path and archive_path != source_path and os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                    LOGGER.info(
                        "🧹 Removed temporary archive %s",
                        archive_path,
                    )
                except Exception:
                    LOGGER.exception("Temp cleanup failed")
            raise LogaltyRESTException(f"Upload failed: {exp}") from exp



    def _resolve_package_type(self, package, source_path):
        """
        Returns: "AIP" or "DIP"
        Priority:
        1. package.package_type
        2. fallback heuristic (7z + path rules)
        """

        # -------------------------
        # 1. TRUST DATABASE FIRST
        # -------------------------
        package_type = getattr(package, "package_type", None)
        if package_type in ("AIP", "DIP"):
            return package_type

        # -------------------------
        # 2. FALLBACK: FILE TYPE HEURISTIC
        # -------------------------
        if source_path and source_path.endswith(".7z"):
            # optional heuristic:
            # you can improve this with folder naming rules
            if "dip" in source_path.lower():
                return "DIP"
            return "AIP"

        # -------------------------
        # 3. DEFAULT SAFE VALUE
        # -------------------------
        return "AIP"
    # -----------------------
    # DOWNLOAD ENTRYPOINT
    # -----------------------
    def move_to_storage_service(self, src_path, dest_path, dest_space):

        package_uuid = self._extract_package_uuid(src_path)
        package = None
        user_id = None
        object_salt = None

        if package_uuid:
            try:
                from .package import Package
                package = Package.objects.filter(uuid=package_uuid).first()

                if package and package.misc_attributes:
                    user_id = package.misc_attributes.get("user_id")
                    object_salt = package.misc_attributes.get("object_salt")

            except Exception:
                LOGGER.warning("Package lookup failed")

        LOGGER.info("⬇️ [DOWNLOAD] AIP/DIP from src: %s ➡ dest: %s", src_path, dest_path)
        package_type = self._resolve_package_type(package, src_path)
        is_dip = package_type == "DIP"
        is_aip = not is_dip

        url = (
            f"{self.logalty_url}/file/download/aip"
            if is_aip else
            f"{self.logalty_url}/file/download/dip"
        )
        LOGGER.info("📦 Sending download request to: %s", url)

        params = {"origin": src_path}

        if user_id:
            params["user_id"] = user_id
        if object_salt:
            params["object_salt"] = object_salt

        try:
            response = requests.get(
                url,
                params=params,
                stream=True,
                auth=(self.logalty_user, self.logalty_pass),
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )

            response.raise_for_status()

            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            if is_aip:
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(1024 * 1024):
                        if chunk:
                            f.write(chunk)
                LOGGER.info("✅ AIP saved to %s", dest_path)
            else:
                with tempfile.NamedTemporaryFile(suffix=".7z", delete=False) as tmp:
                    for chunk in response.iter_content(1024 * 1024):
                        if chunk:
                            tmp.write(chunk)
                    tmp_path = tmp.name
                    LOGGER.info("✅ DIP extracted to %s", dest_path)
                with py7zr.SevenZipFile(tmp_path, "r") as archive:
                    os.makedirs(dest_path, exist_ok=True)
                    archive.extractall(path=dest_path)

                os.remove(tmp_path)

        except Exception as e:
            LOGGER.error("❌ Download failed: %s", e)
            raise LogaltyRESTException(f"Download failed: {e}") from e