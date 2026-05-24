from django import forms


class SetVaultPasswordForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        min_length=8,
        label="Hasło sejfu",
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        label="Potwierdź hasło",
    )

    def clean(self):
        cleaned = super().clean()
        pw = cleaned.get("password")
        pw2 = cleaned.get("password_confirm")
        if pw and pw2 and pw != pw2:
            raise forms.ValidationError("Hasła nie pasują do siebie.")
        return cleaned


class VaultUnlockForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
        label="Hasło sejfu",
    )


class UploadFileForm(forms.Form):
    file = forms.FileField(label="Wybierz plik")
    vault_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
        label="Hasło sejfu",
    )
