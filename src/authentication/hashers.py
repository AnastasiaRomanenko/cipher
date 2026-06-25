from django.conf import settings
from django.contrib.auth.hashers import Argon2PasswordHasher


class ConfigurableArgon2PasswordHasher(Argon2PasswordHasher):
    algorithm = "argon2"

    time_cost = getattr(settings, "ARGON2_TIME_COST", 3)
    memory_cost = getattr(settings, "ARGON2_MEMORY_COST", 65536)
    parallelism = getattr(settings, "ARGON2_PARALLELISM", 4)
