from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.forms import SetPasswordForm, UserCreationForm
from email_validator import EmailNotValidError, validate_email

from src.authentication.lockout import (
    get_lockout_remaining,
    lockout_message,
    record_failure,
    record_success,
)
from src.authentication.totp import get_device, normalize_totp_code, verify_code

Users = get_user_model()


class RegistrationForm(UserCreationForm):
    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Hasło",
                "required": True,
            }
        ),
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Powtórz hasło",
                "required": True,
            }
        ),
    )
    accept_terms_and_conditions = forms.BooleanField(
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-control",
                "type": "checkbox",
                "name": "accept_terms_and_conditions",
                "required": True,
            }
        ),
    )

    class Meta:
        model = Users
        fields = ["first_name", "last_name", "email"]
        widgets = {
            "first_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Imię",
                    "required": True,
                }
            ),
            "last_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Nazwisko",
                    "required": True,
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Email",
                    "required": True,
                }
            ),
        }

    def clean_email(self):
        email = self.cleaned_data["email"]
        if Users.objects.filter(email=email).exists():
            raise forms.ValidationError(
                "Ten adres email już istnieje. Wybierz inny."
            )
        return email


class UserLoginForm(forms.Form):
    login = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Email",
                "required": True,
            }
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Hasło",
                "required": True,
            }
        )
    )

    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request

    def clean(self):
        login = self.cleaned_data.get("login")
        password = self.cleaned_data.get("password")

        if not login or not password:
            return self.cleaned_data

        try:
            validate_email(login)
        except EmailNotValidError:
            raise forms.ValidationError("Nieprawidłowy email.")

        remaining = get_lockout_remaining(login)
        if remaining:
            raise forms.ValidationError(lockout_message(remaining))

        user = authenticate(email=login, password=password)  # EmailAuthBackend
        if not user:
            record_failure(login, self.request)
            remaining = get_lockout_remaining(login)
            if remaining:
                raise forms.ValidationError(lockout_message(remaining))
            raise forms.ValidationError("Nieprawidłowy email lub hasło.")

        record_success(login, self.request)
        self.cleaned_data["user"] = user
        return self.cleaned_data


class AdminLoginForm(forms.Form):
    login = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Email",
                "required": True,
            }
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Hasło",
                "required": True,
            }
        )
    )

    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request

    def clean(self):
        email = self.cleaned_data.get("login")
        password = self.cleaned_data.get("password")

        if not email or not password:
            return self.cleaned_data

        remaining = get_lockout_remaining(email)
        if remaining:
            raise forms.ValidationError(lockout_message(remaining))

        user = authenticate(email=email, password=password)  # EmailAuthBackend
        if not user:
            record_failure(email, self.request)
            remaining = get_lockout_remaining(email)
            if remaining:
                raise forms.ValidationError(lockout_message(remaining))
            raise forms.ValidationError("Nieprawidłowy email lub hasło.")

        record_success(email, self.request)

        if not getattr(user, "is_staff", False):
            raise forms.ValidationError("Brak uprawnień administratora.")

        self.cleaned_data["user"] = user
        return self.cleaned_data


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Email",
                "required": True,
            }
        )
    )

    def clean_email(self):
        email = self.cleaned_data["email"].strip()
        return email


def _clean_totp_code(code):
    code = normalize_totp_code(code)
    if len(code) != 6 or not code.isdigit():
        raise forms.ValidationError("Wpisz 6-cyfrowy kod z aplikacji uwierzytelniającej.")
    return code


class EmailTotpCodeForm(forms.Form):

    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Email",
                "required": True,
            }
        )
    )
    code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Kod z aplikacji",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "required": True,
            }
        ),
    )

    def __init__(self, *args, user_queryset=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_queryset = user_queryset if user_queryset is not None else Users.objects.all()
        self.user = None

    def clean_code(self):
        return _clean_totp_code(self.cleaned_data["code"])

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        code = cleaned_data.get("code")

        if not email or not code:
            return cleaned_data

        try:
            user = self.user_queryset.get(email__iexact=email.strip())
        except Users.DoesNotExist:
            raise forms.ValidationError("Nieprawidłowy kod uwierzytelniający.")

        if not verify_code(get_device(user), code, confirmed_required=True):
            raise forms.ValidationError("Nieprawidłowy kod uwierzytelniający.")

        self.user = user
        return cleaned_data


class AuthenticatorEnrollForm(forms.Form):

    code = forms.CharField(
        min_length=6,
        max_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Kod z aplikacji",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "required": True,
            }
        ),
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_code(self):
        return _clean_totp_code(self.cleaned_data["code"])

    def clean(self):
        cleaned_data = super().clean()
        code = cleaned_data.get("code")
        if not code:
            return cleaned_data

        if not verify_code(get_device(self.user), code, confirmed_required=False):
            raise forms.ValidationError("Nieprawidłowy kod. Zeskanuj kod QR i spróbuj ponownie.")

        return cleaned_data


class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Hasło",
                "required": True,
            }
        )
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Powtórz hasło",
                "required": True,
            }
        )
    )
