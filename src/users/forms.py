from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm

Users = get_user_model()

class UserForm(forms.ModelForm):
    password1 = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"class": "form-control"}))
    password2 = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"class": "form-control"}))

    class Meta:
        model = Users
        fields = ["last_name", "first_name", "email"]
        widgets = {
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.instance or not self.instance.pk:
            self.fields["password1"].required = True
            self.fields["password2"].required = True

    def clean_email(self):
        email = self.cleaned_data.get("email")
        qs = Users.objects.filter(email=email)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)  # exclude self
        if qs.exists():
            raise forms.ValidationError("Użytkownik z tym adresem email już istnieje.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if self.instance and self.instance.pk:
            if password1 or password2:
                if password1 != password2:
                    raise forms.ValidationError("Hasła nie są takie same.")
        else:
            if not password1 or not password2:
                raise forms.ValidationError("Hasło jest wymagane.")
            if password1 != password2:
                raise forms.ValidationError("Hasła nie są takie same.")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password1 = self.cleaned_data.get("password1")

        if password1:
            user.set_password(password1)

        if commit:
            user.save()

        return user


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

    def save(self, commit=True):
        user = super().save(commit=False)
        password1 = self.cleaned_data.get("new_password1")

        if password1:
            user.set_password(password1)
            user.is_active = True

        if commit:
            user.save()

        return user
