from django.urls import path
from src.users.views import users
from django.contrib.auth import views as auth_views

app_name = "users"

urlpatterns = [
    path("users/", users.UsersListView.as_view(), name="user_list"),
    path("users/create/", users.UserCreateView.as_view(), name="user_create"),
    path("users/<int:pk>/profile/", users.UserProfileView.as_view(), name="user_profile"),
    path("users/<int:pk>/update/", users.UserUpdateView.as_view(), name="user_update"),
    path("users/<int:pk>/delete/", users.UserDeleteView.as_view(), name="user_delete"),
    path("users/<int:pk>/invite/", users.UserInviteView.as_view(), name="user_invite"),

    path(
        "set_password/verify/",
        users.InvitationCodeVerifyView.as_view(),
        name="set_password_verify",
    ),
    path(
        "set_password/",
        users.InvitationSetPasswordView.as_view(),
        name="set_password",
    ),

    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="users/invitation_complete.html"
        ),
        name="invitation_complete",
    ),
]
