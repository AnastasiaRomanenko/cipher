import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.views import View
from django.views.generic import CreateView

from src.authentication.forms import EmailTotpCodeForm, RegistrationForm
from src.authentication.tasks import send_bulk_emails
from src.authentication.totp import (
    PURPOSE_REGISTRATION,
    consume_email_totp_code,
    create_email_totp_code,
    get_totp_timeout_minutes,
)

Users = get_user_model()


class CustomRegistrationView(CreateView):
    form_class = RegistrationForm
    template_name = "registration/registration_form.html"
    subject_template_name = "registration/confirmation_subject.txt"
    html_email_template_name = "registration/confirmation_email.html"
    success_url = reverse_lazy("authentication:registration_done")

    def get(self, request, *args, **kwargs):
        return render(
            request,
            self.template_name,
            {
                "form": self.form_class(),
                "site_key": settings.RECAPTCHA_SITE_KEY,
            },
        )

    def post(self, request, *args, **kwargs):
        # reCAPTCHA v2 checkbox
        recaptcha_response = request.POST.get("g-recaptcha-response", "")
        verify = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": settings.RECAPTCHA_SECRET_KEY,
                "response": recaptcha_response,
                "remoteip": request.META.get("REMOTE_ADDR"),
            },
            timeout=5,
        ).json()

        if not verify.get("success"):
            return render(
                request,
                self.template_name,
                {
                    "form": self.form_class(),
                    "site_key": settings.RECAPTCHA_SITE_KEY,
                },
            )

        form = self.form_class(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "site_key": settings.RECAPTCHA_SITE_KEY,
                },
            )
        user = form.save(commit=False)
        user.save()

        code = create_email_totp_code(user, PURPOSE_REGISTRATION)
        subject = "Potwierdzenie konta"

        body = render_to_string(
            self.html_email_template_name,
            {
                "user": user,
                "code": code,
                "code_expiry_minutes": get_totp_timeout_minutes(),
                "verify_url": request.build_absolute_uri(
                    reverse("authentication:registration_complete")
                ),
            },
        )

        send_bulk_emails.delay(subject, body, user.email)
        return redirect("authentication:registration_done")


class RegistrationCompleteView(View):
    form_class = EmailTotpCodeForm
    code_template_name = "registration/registration_code_form.html"
    template_name = "registration/registration_complete.html"
    invalid_template_name = "registration/registration_invalid.html"

    def get(self, request, *args, **kwargs):
        return render(
            request,
            self.code_template_name,
            {
                "form": self.form_class(
                    purpose=PURPOSE_REGISTRATION,
                    user_queryset=Users.objects.filter(is_active=False),
                )
            },
        )

    def post(self, request, *args, **kwargs):
        form = self.form_class(
            request.POST,
            purpose=PURPOSE_REGISTRATION,
            user_queryset=Users.objects.filter(is_active=False),
        )
        if not form.is_valid():
            return render(request, self.code_template_name, {"form": form})

        consume_email_totp_code(
            form.user.email,
            form.cleaned_data["code"],
            PURPOSE_REGISTRATION,
        )
        form.user.is_active = True
        form.user.save(update_fields=["is_active"])
        return render(request, self.template_name)
