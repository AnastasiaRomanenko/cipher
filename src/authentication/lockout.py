import math
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from src.authentication.models import LoginAttempt


def get_failure_limit():
    return int(getattr(settings, "LOGIN_FAILURE_LIMIT", 3))


def get_lockout_seconds():
    return int(getattr(settings, "LOGIN_FAILURE_LOCKOUT_SECONDS", 60))


def get_client_ip(request):
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _recent_failures(email):
    window_start = timezone.now() - timedelta(seconds=get_lockout_seconds())
    return LoginAttempt.objects.filter(
        email__iexact=email,
        successful=False,
        timestamp__gte=window_start,
    ).order_by("timestamp")


def get_lockout_remaining(email):
    if not email:
        return 0
    failures = list(_recent_failures(email))
    if len(failures) < get_failure_limit():
        return 0
    # The lock lifts once the earliest in-window failure expires.
    unlock_at = failures[0].timestamp + timedelta(seconds=get_lockout_seconds())
    remaining = (unlock_at - timezone.now()).total_seconds()
    return max(0, math.ceil(remaining))


def is_locked(email):
    return get_lockout_remaining(email) > 0


def lockout_message(remaining):
    return (
        "Konto zostało tymczasowo zablokowane po wielu nieudanych próbach "
        f"logowania. Spróbuj ponownie za {remaining} s."
    )


def record_failure(email, request=None):
    LoginAttempt.objects.create(
        email=email,
        ip_address=get_client_ip(request),
        successful=False,
    )


def record_success(email, request=None):
    LoginAttempt.objects.create(
        email=email,
        ip_address=get_client_ip(request),
        successful=True,
    )
    LoginAttempt.objects.filter(email__iexact=email, successful=False).delete()
