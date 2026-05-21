from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import redirect_to_login

class SuperuserRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        user = self.request.user
        return (
            user.is_authenticated
            and user.is_staff
            and user.is_superuser
            and user.is_active
        )

    def handle_no_permission(self):
        return redirect_to_login(self.request.get_full_path())
