from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


User = get_user_model()


class Command(BaseCommand):
    help = "Create a minimal seed user for local development."

    def handle(self, *args, **options):
        email = "seed@example.com"
        username = "seeduser"
        password = "SeedPass123!"

        user, created = User.objects.get_or_create(
            email=email,
            defaults={"username": username},
        )
        if created:
            user.set_password(password)
            user.save(update_fields=["password"])
            self.stdout.write(
                self.style.SUCCESS(
                    "Seed user created: email=seed@example.com password=SeedPass123!"
                )
            )
        else:
            self.stdout.write(self.style.WARNING("Seed user already exists."))
