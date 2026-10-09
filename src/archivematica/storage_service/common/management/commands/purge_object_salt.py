"""Remove the object_salt that packages keep in clear in Package.misc_attributes (IPDS-650).

ipds-storage reads the salt from the ipds database, so the Storage Service has no reason to keep a copy. A copy here also
defeats crypto-erasure: destroying the salt in ipds would not stop the package from being decrypted with this one.

The command is idempotent and never prints a salt. With --dry-run it only counts.

Execution example:
./manage.py purge_object_salt --dry-run
./manage.py purge_object_salt
"""

from archivematica.storage_service.common.management.commands import (
    StorageServiceCommand,
)
from archivematica.storage_service.locations.models.package import Package

OBJECT_SALT = "object_salt"


class Command(StorageServiceCommand):
    help = __doc__

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Count the packages that carry a salt without changing them",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        examined = 0
        with_salt = 0

        for package in Package.objects.only("id", "misc_attributes").iterator():
            examined += 1
            attributes = package.misc_attributes
            if not isinstance(attributes, dict) or OBJECT_SALT not in attributes:
                continue
            with_salt += 1
            if dry_run:
                continue
            remaining = {k: v for k, v in attributes.items() if k != OBJECT_SALT}
            # update() instead of save(): nothing else about the package may change as a side effect.
            Package.objects.filter(pk=package.pk).update(misc_attributes=remaining)

        verb = "carry" if dry_run else "carried (now purged)"
        self.success(
            f"{examined} packages examined, {with_salt} {verb} an {OBJECT_SALT}."
        )
