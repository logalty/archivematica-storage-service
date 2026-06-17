from django.db import migrations
from django.db import models


class Migration(migrations.Migration):
    dependencies = [("locations", "0038_Logalty")]
    operations = [
        migrations.AddField(
            model_name="logalty",
            name="s3_endpoint_url",
            preserve_default=False,
            field=models.CharField(
                help_text=b"The URL for AWS S3 on which upload the files before encryption",
                max_length=2048,
                default="",
            ),
        ),
        migrations.AddField(
            model_name="logalty",
            name="s3_region",
            preserve_default=False,
            field=models.CharField(
                help_text=b"The REGION for AWS S3 on which upload the files before encryption",
                max_length=64,
                default="",
            ),
        ),
        migrations.AddField(
            model_name="logalty",
            name="s3_access_key_id",
            field=models.CharField(
                help_text=b"The USER_ID for AWS S3 on which upload the files before encryption",
                max_length=64,
                blank=True,
            ),
        ),
        migrations.AddField(
            model_name="logalty",
            name="s3_secret_access_key",
            field=models.CharField(
                help_text=b"The SECRET for AWS S3 on which upload the files before encryption",
                max_length=256,
                blank=True,
            ),
        ),
        migrations.AddField(
            model_name="logalty",
            name="s3_bucket",
            field=models.CharField(
                help_text=b"The s3 BUCKET for AWS S3 on which upload the files before encryption",
                max_length=64,
                blank=True,
            ),
        ),
    ]
