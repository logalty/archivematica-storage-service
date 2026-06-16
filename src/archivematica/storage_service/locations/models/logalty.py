import os
import logging
import traceback
import requests
import boto3
import botocore
import io
import re
import py7zr
import tempfile

from django.db import models
from .location import Location
from django.utils.translation import gettext_lazy as _

LOGGER = logging.getLogger(__name__)
# Global constants
LOGGER = logging.getLogger(__name__)
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
DS_SCHEME = "https"
DFLT_AS_PORT = 8089
DFLT_DS_PORT = 443

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

    def _ensure_bucket_exists(self):
        try:
            self.s3.meta.client.head_bucket(Bucket=self.s3_bucket)
        except botocore.exceptions.ClientError:
            if self.s3_region == "us-east-1":
                self.s3.create_bucket(Bucket=self.s3_bucket)
            else:
                self.s3.create_bucket(
                    Bucket=self.s3_bucket,
                    CreateBucketConfiguration={"LocationConstraint": self.s3_region},
                )

    # -----------------------
    # DELETE OPTIONAL
    # -----------------------
    def delete_path(self, delete_path):
        url = f"{self.logalty_url}/file"

        try:
            r = requests.delete(
                url,
                params={"destination": delete_path},
                auth=(self.logalty_user, self.logalty_pass),
            )
            r.raise_for_status()
        except Exception as e:
            raise LogaltyRESTException("Delete failed", url=url, exc_info=True)

    # -----------------------
    # CORE FLOW
    # -----------------------
    def _upload_then_encrypt(self, file_path, s3_key, package=None, is_dip=False):

        self._ensure_bucket_exists()

        filename = os.path.basename(file_path)

        # -----------------------
        # METADATA
        # -----------------------
        meta = {}
        user_id = None
        object_salt = None

        if package and getattr(package, "misc_attributes", None):
            user_id = package.misc_attributes.get("user_id")
            object_salt = package.misc_attributes.get("object_salt")

            if user_id:
                meta["user_id"] = user_id
            if object_salt:
                meta["object_salt"] = object_salt

        extra_args = {"Metadata": meta} if meta else {}

        LOGGER.info("⬆️ Uploading to S3: %s → %s", file_path, s3_key)

        # -----------------------
        # 1. UPLOAD S3
        # -----------------------
        try:
            with open(file_path, "rb") as f:
                self.bucket.upload_fileobj(
                    Fileobj=f,
                    Key=s3_key,
                    ExtraArgs=extra_args if extra_args else None,
                )

            LOGGER.info("✅ S3 upload OK: %s", s3_key)

        except Exception as e:
            LOGGER.error("❌ S3 upload failed: %s", e)
            raise RuntimeError(f"S3 upload failed: {e}")

        # -----------------------
        # 2. CALL SPRING BOOT
        # -----------------------
        try:
            endpoint = "/file/dip" if is_dip else "/file/aip"
            url = f"{self.logalty_url}{endpoint}"

            payload = {
                "destination": s3_key,
                "filename": filename,   # ✅ IMPORTANT
            }

            if user_id:
                payload["user_id"] = user_id
            if object_salt:
                payload["object_salt"] = object_salt

            LOGGER.info("📡 Calling IPDS url %s payload=%s", url, payload)

            r = requests.post(
                url,
                data=payload,
                auth=(self.logalty_user, self.logalty_pass),
                timeout=300,
            )
            r.raise_for_status()

            LOGGER.info("🔐 Encryption triggered: %s", s3_key)
            return s3_key

        # -----------------------
        # 3. ROLLBACK S3
        # -----------------------
        except Exception as e:
            LOGGER.error("❌ Spring Boot failed → rollback S3: %s", e)
            try:
                self.bucket.Object(s3_key).delete()
                LOGGER.info("🗑️ Rollback OK: %s", s3_key)
            except Exception as del_err:
                LOGGER.error("❌ Rollback failed: %s", del_err)

            raise RuntimeError(f"Encryption API failed: {e}")

    # -----------------------
    # ENTRYPOINT UPLOAD FILE OR DIRECTORY
    # -----------------------
    def move_from_storage_service(self, source_path, destination_path, package=None):
        """
        Upload workflow:

        AIP:
            - If Archivematica already produced a .7z AIP -> upload it directly.
            - Otherwise compress into .7z first.

        DIP:
            - Always compress the whole directory/file into a single .7z archive.
            - Upload only one archive.
            - Trigger Spring Boot encryption only after successful upload.

        Rollback:
            - If Spring Boot encryption fails, _upload_then_encrypt()
              removes the uploaded S3 object automatically.
        """

        package_type = getattr(package, "package_type", None)
        is_dip = package_type == "DIP"

        LOGGER.info(
            "⬆️ Upload requested source=%s destination=%s package_type=%s",
            source_path,
            destination_path,
            package_type,
        )

        archive_path = None

        try:

            # --------------------------------------------------
            # AIP already generated as .7z by Archivematica
            # --------------------------------------------------
            if (
                    not is_dip
                    and os.path.isfile(source_path)
                    and source_path.lower().endswith(".7z")
            ):

                LOGGER.info(
                    "📦 AIP already packaged as 7z, uploading directly: %s",
                    source_path,
                )

                archive_path = source_path

            # --------------------------------------------------
            # DIRECTORY -> CREATE SINGLE 7Z
            # --------------------------------------------------
            elif os.path.isdir(source_path):

                archive_name = (
                        os.path.basename(source_path.rstrip(os.sep))
                        + ".7z"
                )

                archive_path = os.path.join(
                    tempfile.gettempdir(),
                    archive_name,
                )

                LOGGER.info(
                    "📦 Compressing directory %s -> %s",
                    source_path,
                    archive_path,
                )

                with py7zr.SevenZipFile(
                        archive_path,
                        mode="w",
                ) as archive:
                    archive.writeall(
                        source_path,
                        arcname=os.path.basename(source_path),
                    )

            # --------------------------------------------------
            # FILE -> CREATE SINGLE 7Z
            # --------------------------------------------------
            elif os.path.isfile(source_path):

                base_name = os.path.basename(source_path)

                archive_name = base_name + ".7z"

                archive_path = os.path.join(
                    tempfile.gettempdir(),
                    archive_name,
                )

                LOGGER.info(
                    "📦 Compressing file %s -> %s",
                    source_path,
                    archive_path,
                )

                with py7zr.SevenZipFile(
                        archive_path,
                        mode="w",
                ) as archive:
                    archive.write(
                        source_path,
                        arcname=base_name,
                    )

            else:
                raise ValueError(
                    f"Invalid source path: {source_path}"
                )

            LOGGER.info(
                "✅ Archive ready: %s (%s bytes)",
                archive_path,
                os.path.getsize(archive_path),
            )

            # --------------------------------------------------
            # BUILD FINAL S3 KEY
            # --------------------------------------------------
            archive_filename = os.path.basename(archive_path)

            destination_path = destination_path.rstrip("/")

            s3_key = (
                f"{destination_path}/{archive_filename}"
            )

            LOGGER.info(
                "☁️ Uploading archive to S3 key: %s",
                s3_key,
            )

            self._upload_then_encrypt(
                archive_path,
                s3_key,
                package=package,
                is_dip=is_dip,
            )

            LOGGER.info(
                "✅ Upload and encryption completed successfully"
            )

        finally:

            # remove temporary archives only
            if (
                    archive_path
                    and archive_path != source_path
                    and os.path.exists(archive_path)
            ):
                try:
                    os.remove(archive_path)

                    LOGGER.info(
                        "🧹 Removed temporary archive %s",
                        archive_path,
                    )

                except Exception as e:
                    LOGGER.warning(
                        "⚠️ Failed removing temporary archive %s: %s",
                        archive_path,
                        e,
                    )

    def move_to_storage_service(self, src_path, dest_path, dest_space):
        """
        Downloads AIP or DIP from Spring Boot API via GET.
        - AIP files (.7z, .zip, etc.) are saved directly as compressed files.
        - DIP folders are downloaded as 7z archives and extracted.
        """
        # Extract package UUID from src_path to query database for user_id and object_salt
        # Pattern: /5178/fb1b/f2ca/429c/94c9/1ed6/7c13/6830/... -> 5178fb1b-f2ca-429c-94c9-1ed67c136830
        package_uuid = None
        user_id = None
        object_salt = None

        uuid_pattern = r'/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/([0-9a-f]{4})/'
        match = re.search(uuid_pattern, src_path)
        if match:
            package_uuid = '-'.join(match.groups())
            try:
                from .package import Package
                package = Package.objects.get(uuid=package_uuid)
                if package.misc_attributes:
                    user_id = package.misc_attributes.get("user_id")
                    object_salt = package.misc_attributes.get("object_salt")
            except Exception as e:
                LOGGER.warning("Could not retrieve package metadata: %s", e)

        LOGGER.info("⬇️ [DOWNLOAD] AIP/DIP from src: %s ➡ dest: %s", src_path, dest_path)

        try:
            # Determine if it's an AIP (compressed file) or DIP (folder to extract)
            is_compressed_aip = src_path.endswith((".7z", ".zip", ".rar", ".tar.gz", ".tar", ".gz", ".pbzip2"))

            if is_compressed_aip:
                LOGGER.info("📦 Treating as AIP file: %s", src_path)
                url = f"{self.logalty_url}/file/download/aip"
            else:
                LOGGER.info("📂 Treating as DIP folder: %s", src_path)
                url = f"{self.logalty_url}/file/download/dip"

            # Build params with origin and metadata
            params = {"origin": src_path}

            # Add user_id and object_salt to GET params if available
            if user_id:
                params["user_id"] = user_id
            if object_salt:
                params["object_salt"] = object_salt

            response = requests.get(url, params=params, stream=True, auth=(self.logalty_user, self.logalty_pass))
            response.raise_for_status()

            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            if is_compressed_aip:
                # Save AIP as a file without decompressing
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                LOGGER.info("✅ AIP saved to %s", dest_path)
            else:
                # DIP comes as a 7z archive and needs to be extracted
                with py7zr.SevenZipFile(io.BytesIO(response.content), mode='r') as archive:
                    os.makedirs(dest_path, exist_ok=True)
                    archive.extractall(path=dest_path)
                LOGGER.info("✅ DIP extracted to %s", dest_path)

        except requests.RequestException as e:
            LOGGER.error("❌ HTTP request failed: %s", e)
            raise LogaltyRESTException(f"Error downloading file via GET: {e}")
        except py7zr.Bad7zFile as e:
            LOGGER.error("❌ Failed to extract 7z content: %s", e)
            raise LogaltyRESTException(f"Error extracting downloaded 7z file: {e}")
        except Exception as e:
            LOGGER.error("❌ Unexpected error: %s", e)
            raise LogaltyRESTException(f"Error in move_to_storage_service: {e}")