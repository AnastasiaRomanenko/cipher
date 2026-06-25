import gzip
import math
import os
import re
from functools import lru_cache

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

POOL_LOWER = 26
POOL_UPPER = 26
POOL_DIGITS = 10
POOL_SPECIAL = 33
POOL_OTHER = 100

_SPECIAL_RE = re.compile(r"[ -/:-@\[-`{-~]")
_STRENGTH_BUCKETS = [
    (128, 4, _("Bardzo silne")),
    (60, 3, _("Silne")),
    (36, 2, _("Średnie")),
    (28, 1, _("Słabe")),
    (0, 0, _("Bardzo słabe")),
]


def _wordlist_path():
    default = os.path.join(os.path.dirname(__file__), "data", "wordlist_pl.txt.gz")
    return getattr(settings, "COMMON_PASSWORDS_PATH", default)


@lru_cache(maxsize=1)
def get_common_passwords():
    path = _wordlist_path()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


def is_common_password(password):
    if not password:
        return False
    return password.strip().lower() in get_common_passwords()


def character_pool(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += POOL_LOWER
    if re.search(r"[A-Z]", password):
        pool += POOL_UPPER
    if re.search(r"[0-9]", password):
        pool += POOL_DIGITS
    if _SPECIAL_RE.search(password):
        pool += POOL_SPECIAL
    if re.search(r"[^\x00-\x7f]", password):
        pool += POOL_OTHER
    return pool


def calculate_entropy(password):
    if not password:
        return 0.0
    pool = character_pool(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def evaluate_password(password):
    password = password or ""
    common = is_common_password(password)
    entropy = calculate_entropy(password)

    if common:
        score, label = 0, _("Bardzo słabe")
    else:
        for threshold, score, label in _STRENGTH_BUCKETS:
            if entropy >= threshold:
                break

    return {
        "length": len(password),
        "entropy": round(entropy, 1),
        "pool": character_pool(password),
        "is_common": common,
        "score": score,
        "label": str(label),
    }


class CommonPasswordValidator:
    def validate(self, password, user=None):
        if is_common_password(password):
            raise ValidationError(
                _("To hasło jest zbyt popularne i znajduje się na liście wycieków."),
                code="password_too_common",
            )

    def get_help_text(self):
        return _("Twoje hasło nie może być hasłem powszechnie używanym.")


class PasswordComplexityValidator:

    def __init__(self, min_classes=3):
        self.min_classes = min_classes

    def _classes_present(self, password):
        return sum(
            bool(rx.search(password))
            for rx in (
                re.compile(r"[a-z]"),
                re.compile(r"[A-Z]"),
                re.compile(r"[0-9]"),
                _SPECIAL_RE,
            )
        )

    def validate(self, password, user=None):
        if self._classes_present(password) < self.min_classes:
            raise ValidationError(
                _(
                    "Hasło musi zawierać co najmniej %(min)d z czterech rodzajów znaków: "
                    "małe litery, wielkie litery, cyfry, znaki specjalne."
                ),
                code="password_not_complex",
                params={"min": self.min_classes},
            )

    def get_help_text(self):
        return _(
            "Hasło musi zawierać co najmniej %(min)d z czterech rodzajów znaków: "
            "małe litery, wielkie litery, cyfry, znaki specjalne."
        ) % {"min": self.min_classes}
