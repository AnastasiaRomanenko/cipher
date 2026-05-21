import requests
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy

from src.authentication.forms import AdminLoginForm, UserLoginForm


class CustomLoginView(LoginView):
    template_name = "login/form.html"
    user_form = UserLoginForm
    admin_form = AdminLoginForm
    success_url = reverse_lazy("authentication:service_home")

    def get(self, request, *args, **kwargs):
        return render(
            request,
            self.template_name,
            {
                "user_form": self.user_form(),
                "admin_form": self.admin_form(),
                "site_key": settings.RECAPTCHA_SITE_KEY,
                "active_tab": "user",
            },
        )

    def post(self, request, *args, **kwargs):
        login_type = request.POST.get("login_type", "user")
        if login_type == "admin":
            admin_form = self.admin_form(request.POST)
            user_form = self.user_form()
            active_form = admin_form
            active_tab = "admin"
        else:
            user_form = self.user_form(request.POST)
            admin_form = self.admin_form()
            active_form = user_form
            active_tab = "user"

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
                    "user_form": user_form,
                    "admin_form": admin_form,
                    "site_key": settings.RECAPTCHA_SITE_KEY,
                    "active_tab": active_tab,
                },
            )

        if not active_form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "user_form": user_form,
                    "admin_form": admin_form,
                    "site_key": settings.RECAPTCHA_SITE_KEY,
                    "active_tab": active_tab,
                },
            )

        user = active_form.cleaned_data["user"]
        login(request, user)
        if request.POST.get("remember_me"):
            request.session.set_expiry(settings.SESSION_EXPIRE_SECONDS)
        else:
            request.session.set_expiry(0)
        return redirect(self.success_url)
