from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import redirect, get_object_or_404, render
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.views import View
from django.views.generic import DetailView, CreateView, UpdateView, TemplateView
from src.users.mixins import SuperuserRequiredMixin
from src.authentication.forms import EmailTotpCodeForm
from src.authentication.totp import (
    PURPOSE_INVITATION,
    consume_email_totp_code,
    create_email_totp_code,
    get_totp_timeout_minutes,
)
from src.users.forms import CustomSetPasswordForm, UserForm
from src.users.tasks import send_bulk_emails

Users = get_user_model()

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

        code = create_email_totp_code(user, PURPOSE_INVITATION)
        subject = "Zaproszenie do Szyfr24"

        body = render_to_string(
            self.html_email_template_name,
            {
                "user": user,
                "code": code,
                "code_expiry_minutes": get_totp_timeout_minutes(),
                "verify_url": request.build_absolute_uri(
                    reverse("users:set_password_verify")
                ),
            },
        )

        send_bulk_emails.delay(subject, body, user.email)
        messages.success(request, f"Zaproszenie wysłano na {user.email}.")
        return redirect("users:user_list")


class InvitationCodeVerifyView(View):
    form_class = EmailTotpCodeForm
    template_name = "users/invitation_code_form.html"

    def get(self, request, *args, **kwargs):
        return render(
            request,
            self.template_name,
            {
                "form": self.form_class(
                    purpose=PURPOSE_INVITATION,
                    user_queryset=Users.objects.filter(is_active=False),
                )
            },
        )

    def post(self, request, *args, **kwargs):
        form = self.form_class(
            request.POST,
            purpose=PURPOSE_INVITATION,
            user_queryset=Users.objects.filter(is_active=False),
        )
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        consume_email_totp_code(
            form.user.email,
            form.cleaned_data["code"],
            PURPOSE_INVITATION,
        )
        request.session["invitation_user_id"] = form.user.pk
        return redirect("users:set_password")


class InvitationSetPasswordView(View):
    form_class = CustomSetPasswordForm
    template_name = "users/set_password.html"

    def get_user(self, request):
        user_id = request.session.get("invitation_user_id")
        if not user_id:
            return None
        return Users.objects.filter(pk=user_id, is_active=False).first()

    def get(self, request, *args, **kwargs):
        user_id = request.session.get("invitation_user_id")
        if not user_id:
            return redirect("users:set_password_verify")
        user = Users.objects.filter(pk=user_id, is_active=False).first()
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
        request.session.pop("invitation_user_id", None)
        return redirect("users:invitation_complete")
