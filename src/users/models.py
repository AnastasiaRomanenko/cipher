from django.contrib.auth.models import AbstractUser
from django.db import models
from src.users.managers import UserManager


# Create your models here.
class Users(AbstractUser):
    username = None
    is_active = models.BooleanField(default=False)

    email = models.EmailField(unique=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
