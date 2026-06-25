from django.conf import settings
from django.db import models


class TOTPDevice(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_device",
    )
    secret = models.CharField(max_length=64)
    confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"TOTP device for {self.user_id}"


class LoginAttempt(models.Model):
    email = models.EmailField(db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    successful = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["email", "successful", "timestamp"]),
        ]

    def __str__(self):
        status = "ok" if self.successful else "failed"
        return f"{self.email} ({status}) @ {self.timestamp:%Y-%m-%d %H:%M:%S}"
