import os

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

import config.settings as settings

Users = get_user_model()


class Command(BaseCommand):
    help = "Initialize database with sample data for development/testing"
    default_password = "project_admin123"

    def __init__(self):
        super().__init__()
        self.base_path = os.path.join(settings.BASE_DIR, "gallery")

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear existing data before initialization",
        )

    def handle(self, *args, **options):
        if options["clear"]:
            self.stdout.write(self.style.WARNING("Clearing existing data..."))
            self.clear_data()

        self.stdout.write(self.style.SUCCESS("Starting database initialization..."))

        self.create_user(
            "admin@gmail.com",
            self.default_password,
            first_name="Admin",
            last_name="User",
            is_staff=True,
            is_superuser=True,
            is_active=True,
        )

        self.stdout.write(self.style.SUCCESS("Database initialization completed!"))

    def clear_data(self):
        models_to_clear = [
            Users,
        ]

        for model in models_to_clear:
            count = model.objects.count()
            model.objects.all().delete()
            self.stdout.write(f"  Deleted {count} {model.__name__} objects")

    def create_user(self, email, password=None, **defaults):
        user = Users.objects.filter(email=email).first()
        password = password or self.default_password

        if user is None:
            user = Users.objects.create_user(
                email=email,
                password=password,
                **defaults,
            )
            self.stdout.write(self.style.SUCCESS(f"  Created user: {email}"))
            return user

        for field, value in defaults.items():
            setattr(user, field, value)
        user.save()
        self.stdout.write(self.style.SUCCESS(f"  Updated user: {email}"))
        return user