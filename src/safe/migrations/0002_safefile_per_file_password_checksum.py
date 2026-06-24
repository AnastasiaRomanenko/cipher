from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('safe', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='safefile',
            name='file_password_hash',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='safefile',
            name='file_password_salt',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='safefile',
            name='plaintext_checksum',
            field=models.BinaryField(blank=True, max_length=32, null=True),
        ),
    ]
