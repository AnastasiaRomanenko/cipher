import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac

from src.authentication.models import PasswordReset

PURPOSE_REGISTRATION = "registration"
PURPOSE_PASSWORD_RESET = "password_reset"
PURPOSE_INVITATION = "invitation"

DEFAULT_CODE_LENGTH = 6
DEFAULT_TIMEOUT_MINUTES = 10


def get_totp_timeout_minutes():
    return int(getattr(settings, "EMAIL_TOTP_TIMEOUT_MINUTES", DEFAULT_TIMEOUT_MINUTES))


def normalize_totp_code(code):
    return "".join(str(code or "").split())


def create_email_totp_code(user, purpose):
    length = int(getattr(settings, "EMAIL_TOTP_CODE_LENGTH", DEFAULT_CODE_LENGTH))
    code = f"{secrets.randbelow(10 ** length):0{length}d}"
    prefix = _purpose_prefix(purpose)

    PasswordReset.objects.filter(email__iexact=user.email, token__startswith=prefix).delete()
    PasswordReset.objects.create(
        email=user.email,
        token=f"{prefix}{_hash_code(purpose, code)}",
    )
    return code


def verify_email_totp_code(email, code, purpose):
    normalized_code = normalize_totp_code(code)
    if not normalized_code.isdigit():
        return None

    prefix = _purpose_prefix(purpose)
    timeout = timedelta(minutes=get_totp_timeout_minutes())
    expected_token = f"{prefix}{_hash_code(purpose, normalized_code)}"

    codes = PasswordReset.objects.filter(
        email__iexact=email,
        token__startswith=prefix,
        created_at__gte=timezone.now() - timeout,
    ).order_by("-created_at")

    for stored_code in codes:
        if constant_time_compare(stored_code.token, expected_token):
            return stored_code
    return None


def consume_email_totp_code(email, code, purpose):
    stored_code = verify_email_totp_code(email, code, purpose)
    if stored_code:
        PasswordReset.objects.filter(
            email__iexact=email,
            token__startswith=_purpose_prefix(purpose),
        ).delete()
    return stored_code


def _purpose_prefix(purpose):
    return f"{purpose}:"


def _hash_code(purpose, code):
    return salted_hmac(
        f"email-totp-code:{purpose}",
        normalize_totp_code(code),
        secret=settings.SECRET_KEY,
    ).hexdigest()
