from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView

from src.authentication.views.login import CustomLoginView
from src.authentication.views.password_reset import (
    CustomPasswordResetView,
    PasswordResetCodeVerifyView,
    PasswordResetSetPasswordView,
)
from src.authentication.views.password_strength import PasswordStrengthView
from src.authentication.views.registration import (
    CustomRegistrationView,
    RegistrationCompleteView,
)

app_name = "authentication"

urlpatterns = [
    path("", CustomLoginView.as_view(), name="login"),
    path(
        "service/",
        login_required(
            TemplateView.as_view(template_name="service/home.html")
        ),
        name="service_home",
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page=reverse_lazy("authentication:login")),
        name="logout",
    ),

    path(
        "registration/", CustomRegistrationView.as_view(), name="registration"
    ),
    path(
        "password/strength/",
        PasswordStrengthView.as_view(),
        name="password_strength",
    ),
    path(
        "password_reset/",
        CustomPasswordResetView.as_view(),
        name="password_reset",
    ),
    path(
        "password_reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="password_reset/password_reset_done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "password_reset/verify/",
        PasswordResetCodeVerifyView.as_view(),
        name="password_reset_verify",
    ),
    path(
        "reset/password/",
        PasswordResetSetPasswordView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="password_reset/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
    path(
        "registration/done/",
        TemplateView.as_view(
            template_name="registration/registration_done.html"
        ),
        name="registration_done",
    ),
    path(
        "registration/verify/",
        RegistrationCompleteView.as_view(),
        name="registration_complete",
    ),
]
