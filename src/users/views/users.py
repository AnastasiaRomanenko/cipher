from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core import signing
from django.shortcuts import redirect, get_object_or_404, render
from django.template.loader import render_to_string
from django.conf import settings
from django.urls import reverse_lazy, reverse
from django.views import View
from django.views.generic import DetailView, CreateView, UpdateView, TemplateView
from src.users.mixins import SuperuserRequiredMixin
from src.authentication.forms import AuthenticatorEnrollForm
from src.authentication.totp import (
    confirm_device,
    get_or_create_device,
    provisioning_qr_data_uri,
    provisioning_uri,
)
from src.users.forms import CustomSetPasswordForm, UserForm
from src.users.tasks import send_bulk_emails

Users = get_user_model()

INVITE_SESSION_KEY = "invitation_user_id"
INVITATION_TOKEN_SALT = "users.invitation"

class UsersListView(SuperuserRequiredMixin, TemplateView):
    template_name = "users/list.html"
    permission_required = "has_users"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["page_title"] = "Użytkownicy usługi"
        context["managed_users"] = Users.objects.all().order_by("email")
        context["breadcrumbs"] = [
            {
                "title": "Użytkownicy usługi",
                "url": reverse_lazy("users:user_list"),
            },
        ]
        return context

class UserProfileView(SuperuserRequiredMixin, DetailView):
    model = Users
    template_name = "users/info.html"
    context_object_name = "managed_user"
    permission_required = "has_users"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["page_title"] = "Użytkownicy usługi"
        context["breadcrumbs"] = [
            {
                "title": "Użytkownicy usługi",
                "url": reverse_lazy("users:user_list"),
            },
            {
                "title": "Użytkownik",
                "url": reverse_lazy("users:user_profile", kwargs={"pk": self.object.id}),
            },
        ]
        return context

class UserCreateView(SuperuserRequiredMixin, CreateView):
    model = Users
    form_class = UserForm
    template_name = "users/form.html"
    success_url = reverse_lazy("users:user_list")
    permission_required = "has_users"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Użytkownicy usługi"
        context["breadcrumbs"] = [
            {
                "title": "Użytkownicy usługi",
                "url": reverse_lazy("users:user_list"),
            },
            {
                "title": "Nowy użytkownik",
                "url": reverse_lazy("users:user_create"),
            },
        ]
        return context

    def form_valid(self, form):
        response = super().form_valid(form)
        if not self.object.is_staff:
            self.object.is_staff = True
            self.object.save(update_fields=["is_staff"])
        messages.success(self.request, "Użytkownik został utworzony.")
        return response

    def form_invalid(self, form):
        print(form.errors)
        return super().form_invalid(form)

class UserUpdateView(SuperuserRequiredMixin, UpdateView):
    model = Users
    form_class = UserForm
    template_name = "users/form.html"
    success_url = reverse_lazy("users:user_list")
    permission_required = "has_users"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["page_title"] = "Użytkownicy usługi"
        context["breadcrumbs"] = [
            {"title": "Użytkownicy usługi", "url": reverse_lazy("users:user_list")},
            {"title": "Użytkownik", "url": reverse_lazy("users:user_update", kwargs={"pk": self.object.pk})},
        ]
        return context

    def form_valid(self, form):
        print("Form is valid, saving user %s", self.object.pk)
        messages.success(self.request, "Użytkownik został zaktualizowany.")
        return super().form_valid(form)

    def form_invalid(self, form):
        print("Form invalid: %s", form.errors)
        return super().form_invalid(form)

class UserDeleteView(SuperuserRequiredMixin, View):
    model = Users
    success_url = reverse_lazy("users:user_list")
    template_name = None
    permission_required = "has_users"

    def post(self, request, pk, *args, **kwargs):
        obj = get_object_or_404(self.model, pk=pk)
        title = obj.first_name
        obj.delete()
        messages.success(request, f"Użytkownik: {title} został usunięty.")
        return redirect(self.success_url)

class UserInviteView(SuperuserRequiredMixin, DetailView):
    model = Users
    html_email_template_name = "users/invitation_email.html"
    permission_required = "has_users"

    def post(self, request, *args, **kwargs):
        user = self.get_object()

        get_or_create_device(user)
        token = signing.dumps(user.pk, salt=INVITATION_TOKEN_SALT)
        invite_url = request.build_absolute_uri(
            reverse("users:set_password_verify") + f"?token={token}"
        )
        subject = "Zaproszenie do Szyfr24"

        body = render_to_string(
            self.html_email_template_name,
            {
                "user": user,
                "invite_url": invite_url,
                "issuer_name": settings.TOTP_ISSUER_NAME,
            },
        )

        send_bulk_emails.delay(subject, body, user.email)
        messages.success(request, f"Zaproszenie wysłano na {user.email}.")
        return redirect("users:user_list")


class InvitationCodeVerifyView(View):
    form_class = AuthenticatorEnrollForm
    template_name = "users/invitation_code_form.html"
    invalid_template_name = "users/invitation_invalid.html"

    def user_from_token(self, request):
        token = request.GET.get("token")
        if not token:
            return None
        try:
            user_id = signing.loads(
                token,
                salt=INVITATION_TOKEN_SALT,
                max_age=settings.INVITATION_TOKEN_MAX_AGE_SECONDS,
            )
        except signing.BadSignature:
            return None
        return Users.objects.filter(pk=user_id, is_active=False).first()

    def user_from_session(self, request):
        user_id = request.session.get(INVITE_SESSION_KEY)
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
        user = self.user_from_token(request) or self.user_from_session(request)
        if not user:
            return render(request, self.invalid_template_name)

        request.session[INVITE_SESSION_KEY] = user.pk
        return render(
            request, self.template_name, self.enroll_context(user, self.form_class(user))
        )

    def post(self, request, *args, **kwargs):
        user = self.user_from_session(request)
        if not user:
            return render(request, self.invalid_template_name)

        form = self.form_class(user, request.POST)
        if not form.is_valid():
            return render(request, self.template_name, self.enroll_context(user, form))

        confirm_device(get_or_create_device(user))
        return redirect("users:set_password")


class InvitationSetPasswordView(View):
    form_class = CustomSetPasswordForm
    template_name = "users/set_password.html"

    def get_user(self, request):
        user_id = request.session.get(INVITE_SESSION_KEY)
        if not user_id:
            return None
        return Users.objects.filter(pk=user_id, is_active=False).first()

    def get(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("users:set_password_verify")

        return render(request, self.template_name, {"form": self.form_class(user)})

    def post(self, request, *args, **kwargs):
        user = self.get_user(request)
        if not user:
            return redirect("users:set_password_verify")

        form = self.form_class(user, request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        form.save()
        user.is_active = True
        user.save(update_fields=["is_active"])
        request.session.pop(INVITE_SESSION_KEY, None)
        return redirect("users:invitation_complete")
