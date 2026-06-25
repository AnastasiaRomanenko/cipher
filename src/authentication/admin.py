from django.contrib import admin

from src.authentication.models import LoginAttempt, TOTPDevice


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(admin.ModelAdmin):
    list_display = ("user", "confirmed", "created_at")
    list_filter = ("confirmed",)
    search_fields = ("user__email",)
    readonly_fields = ("secret", "created_at")


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("email", "successful", "ip_address", "timestamp")
    list_filter = ("successful",)
    search_fields = ("email", "ip_address")
    readonly_fields = ("email", "successful", "ip_address", "timestamp")
