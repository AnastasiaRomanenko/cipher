import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import CreateView

from src.authentication.forms import AuthenticatorEnrollForm, RegistrationForm
from src.authentication.totp import (
    confirm_device,
    get_or_create_device,
    provisioning_qr_data_uri,
    provisioning_uri,
)

Users = get_user_model()

ENROLL_SESSION_KEY = "totp_enroll_user_id"


class CustomRegistrationView(CreateView):
    form_class = RegistrationForm
    template_name = "registration/registration_form.html"
    success_url = reverse_lazy("authentication:registration_complete")

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

        get_or_create_device(user)
        request.session[ENROLL_SESSION_KEY] = user.pk
        return redirect("authentication:registration_complete")


class RegistrationCompleteView(View):
    form_class = AuthenticatorEnrollForm
    code_template_name = "registration/registration_code_form.html"
    template_name = "registration/registration_complete.html"

    def get_user(self, request):
        user_id = request.session.get(ENROLL_SESSION_KEY)
        if not user_id:
            return None
        return Users.objects.filter(pk=user_id, is_active=False).first()

    def enroll_context(self, user, form):
        device = get_or_create_device(user)
        return {
            "form": form,
            "qr_data_uri": provisioning_qr_data_uri(device),
            "manual_key": device.secret,
            "provisioning_uri": provisioning_uri(device),
            "issuer_name": settings.TOTP_ISSUER_NAME,
            "account_name": user.email,
        }

    def get(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("authentication:registration")

        return render(
            request,
            self.code_template_name,
            self.enroll_context(user, self.form_class(user)),
        )

    def post(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("authentication:registration")

        form = self.form_class(user, request.POST)
        if not form.is_valid():
            return render(
                request, self.code_template_name, self.enroll_context(user, form)
            )

        confirm_device(get_or_create_device(user))
        user.is_active = True
        user.save(update_fields=["is_active"])
        request.session.pop(ENROLL_SESSION_KEY, None)
        return render(request, self.template_name)
