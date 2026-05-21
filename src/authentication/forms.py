from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.forms import SetPasswordForm, UserCreationForm
from email_validator import EmailNotValidError, validate_email

from src.authentication.totp import normalize_totp_code, verify_email_totp_code

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

    def clean(self):
        login = self.cleaned_data.get("login")
        password = self.cleaned_data.get("password")

        if not login or not password:
            return self.cleaned_data

        try:
            validate_email(login)
        except EmailNotValidError:
            raise forms.ValidationError("Nieprawidłowy email.")

        user = authenticate(email=login, password=password)  # EmailAuthBackend
        if not user:
            raise forms.ValidationError("Nieprawidłowy email lub hasło.")

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

    def clean(self):
        email = self.cleaned_data.get("login")
        password = self.cleaned_data.get("password")

        if not email or not password:
            return self.cleaned_data

        user = authenticate(email=email, password=password)  # EmailAuthBackend
        if not user:
            raise forms.ValidationError("Nieprawidłowy email lub hasło.")

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
                "placeholder": "Kod TOTP",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "required": True,
            }
        ),
    )

    def __init__(self, *args, purpose, user_queryset=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.purpose = purpose
        self.user_queryset = user_queryset if user_queryset is not None else Users.objects.all()
        self.user = None

    def clean_code(self):
        code = normalize_totp_code(self.cleaned_data["code"])
        if len(code) != 6 or not code.isdigit():
            raise forms.ValidationError("Wpisz 6-cyfrowy kod TOTP.")
        return code

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        code = cleaned_data.get("code")

        if not email or not code:
            return cleaned_data

        try:
            user = self.user_queryset.get(email__iexact=email.strip())
        except Users.DoesNotExist:
            raise forms.ValidationError("Nieprawidłowy lub wygasły kod TOTP.")

        if not verify_email_totp_code(user.email, code, self.purpose):
            raise forms.ValidationError("Nieprawidłowy lub wygasły kod TOTP.")

        self.user = user
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
