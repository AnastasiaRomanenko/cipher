from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

Users = get_user_model()


class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        email = kwargs.get("email") or username
        if not email or not password:
            return None
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return None

        return user if user.check_password(password) else None

    def get_user(self, user_id):
        try:
            return Users.objects.get(pk=user_id)
        except Users.DoesNotExist:
            return None
