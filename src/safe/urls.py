from django.urls import path
from . import views

app_name = "safe"

urlpatterns = [
    path("", views.vault_index, name="index"),
    path("set-password/", views.set_password, name="set_password"),
    path("unlock/", views.unlock, name="unlock"),
    path("lock/", views.lock, name="lock"),
    path("upload/", views.upload_file, name="upload"),
    path("download/<int:file_id>/", views.download_file, name="download"),
    path("delete/<int:file_id>/", views.delete_file, name="delete"),
]
