from django.contrib.auth import get_user_model
from django.contrib.auth.views import PasswordResetView
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.views import View

from src.authentication.forms import (
    CustomSetPasswordForm,
    EmailTotpCodeForm,
    PasswordResetRequestForm,
)
from src.authentication.tasks import send_bulk_emails
from src.authentication.totp import (
    PURPOSE_PASSWORD_RESET,
    consume_email_totp_code,
    create_email_totp_code,
    get_totp_timeout_minutes,
)

Users = get_user_model()


class CustomPasswordResetView(PasswordResetView):
    form_class = PasswordResetRequestForm
    template_name = "password_reset/password_reset_form.html"
    html_email_template_name = "password_reset/password_reset_email.html"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {"form": self.form_class()})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        email = form.cleaned_data["email"]
        user = Users.objects.filter(email__iexact=email).first()

        if user:
            code = create_email_totp_code(user, PURPOSE_PASSWORD_RESET)

            body = (
                render_to_string(
                    self.html_email_template_name,
                    {
                        "user": user,
                        "code": code,
                        "code_expiry_minutes": get_totp_timeout_minutes(),
                        "verify_url": request.build_absolute_uri(
                            reverse("authentication:password_reset_verify")
                        ),
                    },
                )
                .strip()
                .replace("\n", "")
            )

            send_bulk_emails.delay("Przywracanie hasła", body, email)
        return redirect("authentication:password_reset_done")


class PasswordResetCodeVerifyView(View):
    form_class = EmailTotpCodeForm
    template_name = "password_reset/password_reset_code_form.html"

    def get(self, request, *args, **kwargs):
        return render(
            request,
            self.template_name,
            {"form": self.form_class(purpose=PURPOSE_PASSWORD_RESET)},
        )

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST, purpose=PURPOSE_PASSWORD_RESET)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        consume_email_totp_code(
            form.user.email,
            form.cleaned_data["code"],
            PURPOSE_PASSWORD_RESET,
        )
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
