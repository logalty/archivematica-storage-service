from django.db import migrations
from django.db import models


class Migration(migrations.Migration):
    dependencies = [("locations", "0037_django42")]
    operations = [
        migrations.CreateModel(
            name="Logalty",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "logalty_url",
                    models.CharField(
                        help_text="Logalty Storage Module Endpoint URL.",
                        max_length=2048,
                        verbose_name="Logalty Storage Module Endpoint URL",
                    ),
                ),
                (
                    "logalty_user",
                    models.CharField(
                        help_text=b"DSpace username to authenticate as", max_length=64
                    ),
                ),
                (
                    "logalty_pass",
                    models.CharField(
                        help_text=b"DSpace password to authenticate with", max_length=64
                    ),
                ),
            ],
            options={"verbose_name": "Logalty Storage Module via REST API"},
            bases=(models.Model,),
        ),
        migrations.AlterField(
            model_name="space",
            name="access_protocol",
            field=models.CharField(
                help_text=b"How the space can be accessed.",
                max_length=8,
                choices=[
                    (b"ARKIVUM", "Arkivum"),
                    (b"DV", "Dataverse"),
                    (b"DC", "DuraCloud"),
                    (b"DSPACE", "DSpace via SWORD2 API"),
                    (b"FEDORA", "FEDORA via SWORD2"),
                    (b"GPG", "GPG encryption on Local Filesystem"),
                    (b"FS", "Local Filesystem"),
                    (b"LOM", "LOCKSS-o-matic"),
                    (b"NFS", "NFS"),
                    (b"PIPE_FS", "Pipeline Local Filesystem"),
                    (b"SWIFT", "Swift"),
                    (b"S3", "S3"),
                    (b"LOGALTY", "Logalty Storage Module via REST API"),
                ],
            ),
        ),
        migrations.AddField(
            model_name="logalty",
            name="space",
            field=models.OneToOneField(
                to="locations.Space", to_field="uuid", on_delete=models.CASCADE
            ),
        ),
    ]
