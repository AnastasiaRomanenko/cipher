from django.contrib.auth import get_user_model
from django.contrib.auth.views import PasswordResetView
from django.shortcuts import redirect, render
from django.views import View

from src.authentication.forms import (
    CustomSetPasswordForm,
    EmailTotpCodeForm,
    PasswordResetRequestForm,
)

Users = get_user_model()


class CustomPasswordResetView(PasswordResetView):
    form_class = PasswordResetRequestForm
    template_name = "password_reset/password_reset_form.html"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {"form": self.form_class()})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        # No email is sent: the user proves identity with a code from their
        # already-enrolled authenticator app on the next step.
        return redirect("authentication:password_reset_done")


class PasswordResetCodeVerifyView(View):
    form_class = EmailTotpCodeForm
    template_name = "password_reset/password_reset_code_form.html"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {"form": self.form_class()})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        request.session["password_reset_user_id"] = form.user.pk
        return redirect("authentication:password_reset_confirm")


class PasswordResetSetPasswordView(View):
    form_class = CustomSetPasswordForm
    template_name = "password_reset/password_reset_confirm.html"

    def get_user(self, request):
        user_id = request.session.get("password_reset_user_id")
        if not user_id:
            return None
        return Users.objects.filter(pk=user_id).first()

    def get(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("authentication:password_reset_verify")

        return render(request, self.template_name, {"form": self.form_class(user)})

    def post(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("authentication:password_reset_verify")

        form = self.form_class(user, request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        form.save()
        request.session.pop("password_reset_user_id", None)
        return redirect("authentication:password_reset_complete")
