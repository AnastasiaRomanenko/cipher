import pyotp
import segno
from django.conf import settings

from src.authentication.models import TOTPDevice

VALID_WINDOW = 1


def normalize_totp_code(code):
    return "".join(str(code or "").split())


def get_or_create_device(user):
    device, _ = TOTPDevice.objects.get_or_create(
        user=user,
        defaults={"secret": pyotp.random_base32()},
    )
    return device


def get_device(user):
    return getattr(user, "totp_device", None)


def provisioning_uri(device):
    return pyotp.TOTP(device.secret).provisioning_uri(
        name=device.user.email,
        issuer_name=settings.TOTP_ISSUER_NAME,
    )


def provisioning_qr_data_uri(device):
    return segno.make(provisioning_uri(device), error="m").svg_data_uri(scale=5)


def verify_code(device, code, confirmed_required=True):
    if device is None:
        return False
    if confirmed_required and not device.confirmed:
        return False

    normalized_code = normalize_totp_code(code)
    if not normalized_code.isdigit():
        return False

    return pyotp.TOTP(device.secret).verify(normalized_code, valid_window=VALID_WINDOW)


def confirm_device(device):
    if not device.confirmed:
        device.confirmed = True
        device.save(update_fields=["confirmed"])
    return device
