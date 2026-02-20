import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone

from tasks.models import PasswordResetToken


User = get_user_model()


def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def find_user_by_email(email):
    if not email:
        return None
    return User.objects.filter(email__iexact=email.strip().lower()).first()


def create_user(username, email, password):
    user = User.objects.create_user(
        username=username.strip(),
        email=email.strip().lower(),
        password=password,
    )
    return user


def generate_reset_token(user, ttl_minutes=60):
    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)
    expires_at = timezone.now() + timedelta(minutes=ttl_minutes)

    PasswordResetToken.objects.create(
        user=user,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    return raw_token


def get_valid_reset_token(raw_token):
    token_hash = _hash_token(raw_token)
    now = timezone.now()
    return (
        PasswordResetToken.objects.select_related("user")
        .filter(token_hash=token_hash, used_at__isnull=True, expires_at__gt=now)
        .first()
    )


def mark_reset_token_used(reset_token):
    reset_token.used_at = timezone.now()
    reset_token.save(update_fields=["used_at"])


def invalidate_user_reset_tokens(user):
    PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(
        used_at=timezone.now()
    )


def send_reset_email(request, user, raw_token):
    reset_path = reverse("reset_password", kwargs={"token": raw_token})
    reset_url = request.build_absolute_uri(reset_path)

    subject = "Réinitialisation de mot de passe"
    message = (
        "Une demande de réinitialisation a été effectuée.\n\n"
        f"Utilisez ce lien: {reset_url}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@example.com")
    send_mail(subject, message, from_email, [user.email], fail_silently=True)
