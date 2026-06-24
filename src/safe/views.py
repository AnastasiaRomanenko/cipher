import mimetypes

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render

from .crypto import (
    ChecksumMismatch,
    TamperingDetected,
    compute_plaintext_checksum,
    decrypt_file,
    encrypt_file,
    hash_file_password,
    hash_vault_password,
    verify_file_password,
    verify_plaintext_checksum,
    verify_vault_password,
)
from .forms import DownloadFileForm, SetVaultPasswordForm, UploadFileForm, VaultUnlockForm
from .models import SafeFile, VaultConfig

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@login_required
def vault_index(request):
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
    request.session.pop("vault_unlocked", None)
    return redirect("safe:unlock")


@login_required
def upload_file(request):
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES["file"]
            file_password = form.cleaned_data["file_password"]

            plaintext = uploaded.read()
            if len(plaintext) > MAX_UPLOAD_BYTES:
                messages.error(request, "Plik jest za duży (max 50 MB).")
                return render(request, "safe/upload.html", {"form": form})

            ciphertext, salt, nonce = encrypt_file(file_password, plaintext)
            pw_hash, pw_salt = hash_file_password(file_password)
            checksum = compute_plaintext_checksum(plaintext)

            SafeFile.objects.create(
                user=request.user,
                original_name=uploaded.name,
                encrypted_data=ciphertext,
                salt=salt,
                nonce=nonce,
                file_password_hash=pw_hash,
                file_password_salt=pw_salt,
                plaintext_checksum=checksum,
                file_size=len(plaintext),
            )
            messages.success(request, "Plik '{}' zostal zaszyfrowany i dodany do sejfu.".format(uploaded.name))
            return redirect("safe:index")
    else:
        form = UploadFileForm()
    return render(request, "safe/upload.html", {"form": form})


@login_required
def download_file(request, file_id):
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    safe_file = get_object_or_404(SafeFile, id=file_id, user=request.user)

    if request.method == "POST":
        form = DownloadFileForm(request.POST)
        if form.is_valid():
            file_password = form.cleaned_data["file_password"]

            if safe_file.file_password_hash is None:
                messages.error(request, "Ten plik nie ma przypisanego hasła — pobieranie niemożliwe.")
                return redirect("safe:index")

            if not verify_file_password(
                file_password,
                bytes(safe_file.file_password_hash),
                bytes(safe_file.file_password_salt),
            ):
                messages.error(request, "Nieprawidłowe hasło pliku.")
                return render(request, "safe/download_confirm.html", {"file": safe_file, "form": form})

            try:
                plaintext = decrypt_file(
                    file_password,
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

            if safe_file.plaintext_checksum is not None:
                if not verify_plaintext_checksum(plaintext, bytes(safe_file.plaintext_checksum)):
                    messages.error(
                        request,
                        "BŁĄD SUMY KONTROLNEJ: Zawartość pliku nie zgadza się z oryginałem. Pobieranie anulowane."
                    )
                    return redirect("safe:index")

            mime_type, _ = mimetypes.guess_type(safe_file.original_name)
            response = HttpResponse(plaintext, content_type=mime_type or "application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{safe_file.original_name}"'
            response["Content-Length"] = len(plaintext)
            return response
    else:
        form = DownloadFileForm()

    return render(request, "safe/download_confirm.html", {"file": safe_file, "form": form})


@login_required
def delete_file(request, file_id):
    if not request.session.get("vault_unlocked"):
        return redirect("safe:unlock")

    safe_file = get_object_or_404(SafeFile, id=file_id, user=request.user)

    if request.method == "POST":
        name = safe_file.original_name
        safe_file.delete()
        messages.success(request, "Plik '{}' zostal trwale usuniety.".format(name))
        return redirect("safe:index")

    return render(request, "safe/delete_confirm.html", {"file": safe_file})
