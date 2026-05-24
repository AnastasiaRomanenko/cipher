import mimetypes

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render

from .crypto import (
    TamperingDetected,
    decrypt_file,
    encrypt_file,
    hash_vault_password,
    verify_vault_password,
)
from .forms import SetVaultPasswordForm, UploadFileForm, VaultUnlockForm
from .models import SafeFile, VaultConfig

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@login_required
def vault_index(request):
    """Landing page: shows either 'set password' prompt, unlock form, or file list."""
    try:
        config = request.user.vault_config
    except VaultConfig.DoesNotExist:
        return redirect("safe:set_password")

    unlocked = request.session.get("vault_unlocked", False)
    if not unlocked:
        return redirect("safe:unlock")

    files = SafeFile.objects.filter(user=request.user)
    return render(request, "safe/index.html", {"files": files})


@login_required
def set_password(request):
    """Create or replace the vault password."""
    if request.method == "POST":
        form = SetVaultPasswordForm(request.POST)
        if form.is_valid():
            pw = form.cleaned_data["password"]
            hashed, salt = hash_vault_password(pw)
            VaultConfig.objects.update_or_create(
                user=request.user,
                defaults={
                    "password_hash": bytes(hashed),
                    "password_salt": bytes(salt),
                },
            )
            request.session["vault_unlocked"] = True
            messages.success(request, "Hasło sejfu zostało ustawione.")
            return redirect("safe:index")
    else:
        form = SetVaultPasswordForm()
    return render(request, "safe/set_password.html", {"form": form})


@login_required
def unlock(request):
    """Verify the vault password and mark the session as unlocked."""
    try:
        config = request.user.vault_config
    except VaultConfig.DoesNotExist:
        return redirect("safe:set_password")

    if request.method == "POST":
        form = VaultUnlockForm(request.POST)
        if form.is_valid():
            pw = form.cleaned_data["password"]
            if verify_vault_password(
                pw,
                bytes(config.password_hash),
                bytes(config.password_salt),
            ):
                request.session["vault_unlocked"] = True
                return redirect("safe:index")
            else:
                messages.error(request, "Nieprawidłowe hasło sejfu.")
    else:
        form = VaultUnlockForm()
    return render(request, "safe/unlock.html", {"form": form})


@login_required
def lock(request):
    """Lock the vault by removing the session flag."""
    request.session.pop("vault_unlocked", None)
    return redirect("safe:unlock")


@login_required
def upload_file(request):
    """Encrypt and store an uploaded file."""
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES["file"]
            vault_password = form.cleaned_data["vault_password"]

            # Verify vault password before encrypting
            try:
                config = request.user.vault_config
            except VaultConfig.DoesNotExist:
                messages.error(request, "Najpierw ustaw hasło sejfu.")
                return redirect("safe:set_password")

            if not verify_vault_password(
                vault_password,
                bytes(config.password_hash),
                bytes(config.password_salt),
            ):
                messages.error(request, "Nieprawidłowe hasło sejfu.")
                return render(request, "safe/upload.html", {"form": form})

            plaintext = uploaded.read()
            if len(plaintext) > MAX_UPLOAD_BYTES:
                messages.error(request, "Plik jest za duży (max 50 MB).")
                return render(request, "safe/upload.html", {"form": form})

            ciphertext, salt, nonce = encrypt_file(vault_password, plaintext)

            SafeFile.objects.create(
                user=request.user,
                original_name=uploaded.name,
                encrypted_data=ciphertext,
                salt=salt,
                nonce=nonce,
                file_size=len(plaintext),
            )
            messages.success(request, "Plik '{}' zostal zaszyfrowany i dodany do sejfu.".format(uploaded.name))
            return redirect("safe:index")
    else:
        form = UploadFileForm()
    return render(request, "safe/upload.html", {"form": form})


@login_required
def download_file(request, file_id):
    """Decrypt and serve a file for download."""
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    safe_file = get_object_or_404(SafeFile, id=file_id, user=request.user)

    if request.method == "POST":
        form = VaultUnlockForm(request.POST)
        if form.is_valid():
            pw = form.cleaned_data["password"]
            try:
                config = request.user.vault_config
            except VaultConfig.DoesNotExist:
                raise Http404

            if not verify_vault_password(pw, bytes(config.password_hash), bytes(config.password_salt)):
                messages.error(request, "Nieprawidłowe hasło sejfu.")
                return render(request, "safe/download_confirm.html", {"file": safe_file, "form": form})

            try:
                plaintext = decrypt_file(
                    pw,
                    bytes(safe_file.encrypted_data),
                    bytes(safe_file.salt),
                    bytes(safe_file.nonce),
                )
            except TamperingDetected:
                messages.error(
                    request,
                    "BŁĄD INTEGRALNOŚCI: Zaszyfrowany plik został zmodyfikowany. Pobieranie anulowane."
                )
                return redirect("safe:index")

            mime_type, _ = mimetypes.guess_type(safe_file.original_name)
            response = HttpResponse(plaintext, content_type=mime_type or "application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{safe_file.original_name}"'
            response["Content-Length"] = len(plaintext)
            return response
    else:
        form = VaultUnlockForm()

    return render(request, "safe/download_confirm.html", {"file": safe_file, "form": form})


@login_required
def delete_file(request, file_id):
    """Permanently delete an encrypted file."""
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    safe_file = get_object_or_404(SafeFile, id=file_id, user=request.user)

    if request.method == "POST":
        name = safe_file.original_name
        safe_file.delete()
        messages.success(request, "Plik '{}' zostal trwale usuniety.".format(name))
        return redirect("safe:index")

    return render(request, "safe/delete_confirm.html", {"file": safe_file})
