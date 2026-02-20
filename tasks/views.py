import json
import hashlib
import re
import secrets
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .forms import (
    ForgotPasswordForm,
    LoginForm,
    RegisterForm,
    ResetPasswordForm,
    TaskForm,
)
from .models import Task
from .rate_limit import clear_rate_limit, rate_limit
from .services.auth_service import (
    create_user,
    find_user_by_email,
    generate_reset_token,
    get_valid_reset_token,
    invalidate_user_reset_tokens,
    mark_reset_token_used,
    send_reset_email,
)


User = get_user_model()

TMDB_DISCOVER_TV_URL = "https://api.themoviedb.org/3/discover/tv"
STREAMING_PROVIDERS = {
    "netflix": {"id": "8", "label": "Netflix"},
    "amazon-prime": {"id": "9", "label": "Amazon Prime Video"},
    "apple-tv": {"id": "350", "label": "Apple TV"},
}
FRANCECONNECT_SESSION_STATE_KEY = "franceconnect_oauth_state"
FRANCECONNECT_SESSION_NEXT_KEY = "franceconnect_oauth_next"
FRANCECONNECT_SESSION_NONCE_KEY = "franceconnect_oauth_nonce"


def _safe_next_url(request):
    next_url = request.POST.get("next") or request.GET.get("next")
    if next_url and url_has_allowed_host_and_scheme(
        next_url, allowed_hosts={request.get_host()}
    ):
        return next_url
    return None


def _is_franceconnect_enabled():
    return bool(getattr(settings, "FRANCECONNECT_ENABLED", False))


def _franceconnect_redirect_uri(request):
    configured_redirect_uri = getattr(settings, "FRANCECONNECT_REDIRECT_URI", "").strip()
    if configured_redirect_uri:
        return configured_redirect_uri
    return request.build_absolute_uri(reverse("franceconnect_callback_public"))


def _normalize_username(value):
    normalized = re.sub(r"[^a-z0-9._+-]", "-", (value or "").strip().lower())
    normalized = re.sub(r"-{2,}", "-", normalized).strip("-")
    return normalized or "franceconnect"


def _build_unique_username(userinfo, email, sub):
    preferred = (userinfo.get("preferred_username") or "").strip()
    given_name = (userinfo.get("given_name") or "").strip()
    family_name = (userinfo.get("family_name") or "").strip()
    local_part = email.split("@")[0]
    name_candidate = ".".join(part for part in [given_name, family_name] if part)
    base = preferred or name_candidate or local_part
    if not base and sub:
        base = f"franceconnect-{hashlib.sha256(sub.encode('utf-8')).hexdigest()[:8]}"

    base_username = _normalize_username(base)[:150]
    candidate = base_username
    suffix_index = 1
    while User.objects.filter(username=candidate).exists():
        suffix = f"-{suffix_index}"
        candidate = f"{base_username[:150-len(suffix)]}{suffix}"
        suffix_index += 1
    return candidate


def _get_or_create_franceconnect_user(userinfo):
    email = (userinfo.get("email") or "").strip().lower()
    sub = str(userinfo.get("sub") or "").strip()

    if not email:
        if not sub:
            raise ValueError("Réponse FranceConnect invalide: aucun identifiant utilisateur.")
        email_digest = hashlib.sha256(sub.encode("utf-8")).hexdigest()[:24]
        email = f"franceconnect+{email_digest}@local.invalid"

    user = find_user_by_email(email)
    if user:
        return user, False

    username = _build_unique_username(userinfo, email, sub)
    user = User(username=username, email=email)
    user.set_unusable_password()
    if hasattr(user, "first_name"):
        user.first_name = (userinfo.get("given_name") or "").strip()[:150]
    if hasattr(user, "last_name"):
        user.last_name = (userinfo.get("family_name") or "").strip()[:150]
    user.save()
    return user, True


@rate_limit("login", limit=8, window_seconds=900)
def login_view(request):
    if request.user.is_authenticated:
        return redirect("list")

    form = LoginForm(request.POST or None)
    next_url = _safe_next_url(request)

    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"].strip().lower()
        password = form.cleaned_data["password"]
        remember_me = form.cleaned_data.get("remember_me", False)
        user = authenticate(request, email=email, password=password)

        if user is None:
            form.add_error(None, "Email ou mot de passe invalide.")
        else:
            if hasattr(user, "profile") and not user.profile.email_verified:
                form.add_error(
                    None,
                    "Compte non vérifié. Code: EMAIL_NOT_VERIFIED.",
                )
                return render(
                    request,
                    "registration/login.html",
                    {
                        "form": form,
                        "next": next_url,
                        "franceconnect_enabled": _is_franceconnect_enabled(),
                    },
                    status=403,
                )

            login(request, user)
            if remember_me:
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            else:
                request.session.set_expiry(0)
            clear_rate_limit("login", request)
            return redirect(next_url or "list")

    return render(
        request,
        "registration/login.html",
        {
            "form": form,
            "next": next_url,
            "franceconnect_enabled": _is_franceconnect_enabled(),
        },
    )


def franceconnect_login_view(request):
    if request.user.is_authenticated:
        return redirect("list")
    if not _is_franceconnect_enabled():
        messages.error(request, "FranceConnect n'est pas configuré.")
        return redirect("login")

    next_url = _safe_next_url(request)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    request.session[FRANCECONNECT_SESSION_STATE_KEY] = state
    request.session[FRANCECONNECT_SESSION_NEXT_KEY] = next_url or ""
    request.session[FRANCECONNECT_SESSION_NONCE_KEY] = nonce

    params = {
        "response_type": "code",
        "client_id": settings.FRANCECONNECT_CLIENT_ID,
        "scope": settings.FRANCECONNECT_SCOPE,
        "redirect_uri": _franceconnect_redirect_uri(request),
        "state": state,
        "nonce": nonce,
        "acr_values": getattr(settings, "FRANCECONNECT_ACR_VALUES", "eidas1"),
    }
    return redirect(f"{settings.FRANCECONNECT_AUTHORIZE_URL}?{urlencode(params)}")


def franceconnect_callback_view(request):
    if not _is_franceconnect_enabled():
        messages.error(request, "FranceConnect n'est pas configuré.")
        return redirect("login")

    expected_state = request.session.pop(FRANCECONNECT_SESSION_STATE_KEY, None)
    expected_nonce = request.session.pop(FRANCECONNECT_SESSION_NONCE_KEY, None)
    next_url = request.session.pop(FRANCECONNECT_SESSION_NEXT_KEY, "") or "list"
    returned_state = request.GET.get("state")
    auth_error = request.GET.get("error")
    code = request.GET.get("code")

    if auth_error:
        error_description = request.GET.get("error_description") or "Accès refusé."
        messages.error(request, f"Échec de la connexion FranceConnect: {error_description}")
        return redirect("login")

    if not expected_state or returned_state != expected_state:
        messages.error(request, "Échec de la connexion FranceConnect: état OAuth invalide.")
        return redirect("login")

    if not code:
        messages.error(request, "Échec de la connexion FranceConnect: code manquant.")
        return redirect("login")

    token_data = urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": settings.FRANCECONNECT_CLIENT_ID,
            "client_secret": settings.FRANCECONNECT_CLIENT_SECRET,
            "redirect_uri": _franceconnect_redirect_uri(request),
            "nonce": expected_nonce or "",
        }
    ).encode("utf-8")

    token_request = Request(
        settings.FRANCECONNECT_TOKEN_URL,
        data=token_data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        },
    )

    try:
        with urlopen(token_request, timeout=10) as response:
            token_payload = json.loads(response.read().decode("utf-8"))

        access_token = (token_payload.get("access_token") or "").strip()
        if not access_token:
            raise ValueError("Aucun access token reçu.")

        userinfo_request = Request(
            settings.FRANCECONNECT_USERINFO_URL,
            headers={
                "accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        with urlopen(userinfo_request, timeout=10) as response:
            userinfo = json.loads(response.read().decode("utf-8"))

        user, created = _get_or_create_franceconnect_user(userinfo)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        messages.error(
            request,
            f"Connexion FranceConnect impossible pour le moment ({exc}).",
        )
        return redirect("login")

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    if created:
        messages.success(request, "Compte créé automatiquement via FranceConnect.")
    return redirect(next_url)


def register_view(request):
    if request.user.is_authenticated:
        return redirect("list")

    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = create_user(
            username=form.cleaned_data["username"],
            email=form.cleaned_data["email"],
            password=form.cleaned_data["password"],
        )
        login(request, user, backend="tasks.auth_backends.EmailBackend")
        messages.success(request, "Compte créé avec succès.")
        return redirect("list")

    return render(request, "registration/register.html", {"form": form})


@rate_limit("forgot-password", limit=5, window_seconds=900)
def forgot_password_view(request):
    form = ForgotPasswordForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        user = find_user_by_email(form.cleaned_data["email"])
        if user and user.is_active:
            raw_token = generate_reset_token(user=user, ttl_minutes=60)
            send_reset_email(request, user, raw_token)

        messages.success(
            request,
            "Si ce compte existe, un email de réinitialisation a été envoyé.",
        )
        return redirect("login")

    return render(request, "registration/forgot_password.html", {"form": form})


def reset_password_view(request, token):
    reset_token = get_valid_reset_token(token)
    if reset_token is None:
        messages.error(request, "Lien de réinitialisation invalide ou expiré.")
        return redirect("forgot_password")

    form = ResetPasswordForm(request.POST or None, user=reset_token.user)
    if request.method == "POST" and form.is_valid():
        user = reset_token.user
        user.set_password(form.cleaned_data["password"])
        user.save(update_fields=["password"])

        mark_reset_token_used(reset_token)
        invalidate_user_reset_tokens(user)
        messages.success(request, "Votre mot de passe a été mis à jour.")
        return redirect("login")

    return render(request, "registration/reset_password.html", {"form": form})


def me_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False}, status=401)

    return JsonResponse(
        {
            "authenticated": True,
            "id": request.user.id,
            "username": request.user.username,
            "email": request.user.email,
        }
    )


@login_required
def index(request):
    tasks = Task.objects.filter(user=request.user).order_by("-created")
    form = TaskForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        task = form.save(commit=False)
        task.user = request.user
        task.save()
        return redirect("list")

    context = {"tasks": tasks, "form": form}
    return render(request, "tasks/list.html", context)


def _fetch_top_rated_series(provider_id, limit=10, excluded_series_ids=None):
    token = getattr(settings, "TMDB_READ_ACCESS_TOKEN", "")
    language = getattr(settings, "TMDB_LANGUAGE", "fr-FR")
    watch_region = getattr(settings, "TMDB_WATCH_REGION", "US")

    if not token:
        raise ValueError("TMDB_READ_ACCESS_TOKEN is not configured.")

    excluded_ids = set(excluded_series_ids or [])
    collected_series = []
    page = 1
    total_pages = 1

    while len(collected_series) < limit and page <= total_pages:
        params = {
            "language": language,
            "page": page,
            "sort_by": "vote_average.desc",
            "vote_count.gte": 500,
            "watch_region": watch_region,
            "with_watch_monetization_types": "flatrate",
            "with_watch_providers": provider_id,
        }
        request = Request(
            f"{TMDB_DISCOVER_TV_URL}?{urlencode(params)}",
            headers={
                "accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )

        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))

        total_pages = int(payload.get("total_pages", 1) or 1)
        results = payload.get("results", [])
        for item in results:
            series_id = item.get("id")
            series_name = item.get("name")
            if not series_id or not series_name:
                continue
            if series_id in excluded_ids:
                continue

            excluded_ids.add(series_id)
            collected_series.append(
                {
                    "id": series_id,
                    "name": series_name,
                    "poster_path": item.get("poster_path"),
                }
            )
            if len(collected_series) == limit:
                break

        page += 1

    return collected_series


@login_required
@require_POST
def addProviderWatchlist(request, provider_slug):
    provider = STREAMING_PROVIDERS.get(provider_slug)
    if provider is None:
        messages.error(request, "Plateforme non supportée.")
        return redirect("list")

    existing_provider_series_ids = set(
        Task.objects.filter(user=request.user, provider_service_id=provider["id"])
        .exclude(tmdb_series_id__isnull=True)
        .values_list("tmdb_series_id", flat=True)
    )

    try:
        series_items = _fetch_top_rated_series(
            provider["id"],
            limit=10,
            excluded_series_ids=existing_provider_series_ids,
        )
    except ValueError:
        messages.error(
            request,
            "TMDB_READ_ACCESS_TOKEN manquant. Configurez cette variable d'environnement.",
        )
        return redirect("list")
    except HTTPError as exc:
        if exc.code == 401:
            messages.error(
                request,
                "TMDB a refusé la requête (401). Vérifiez votre Read Access Token.",
            )
        else:
            messages.error(request, f"TMDB a retourné une erreur HTTP ({exc.code}).")
        return redirect("list")
    except URLError:
        messages.error(request, "Impossible de contacter TMDB (problème réseau).")
        return redirect("list")
    except TimeoutError:
        messages.error(request, "TMDB ne répond pas (timeout).")
        return redirect("list")
    except json.JSONDecodeError:
        messages.error(request, "Réponse TMDB invalide. Réessayez dans quelques secondes.")
        return redirect("list")

    created_count = 0
    for item in series_items:
        task_title = f"[{provider['label']}] {item['name']}"
        _, created = Task.objects.get_or_create(
            user=request.user,
            provider_service_id=provider["id"],
            tmdb_series_id=item["id"],
            defaults={
                "title": task_title,
                "complete": False,
                "provider_slug": provider_slug,
                "poster_path": item.get("poster_path"),
            },
        )
        if created:
            created_count += 1

    if created_count:
        messages.success(
            request,
            f"{created_count} séries {provider['label']} ajoutées à votre watchlist.",
        )
    else:
        messages.info(request, f"Aucune nouvelle série {provider['label']} à ajouter.")

    return redirect("list")


@login_required
def updateTask(request, pk):
    task = get_object_or_404(Task, id=pk, user=request.user)
    form = TaskForm(request.POST or None, instance=task)

    if request.method == "POST" and form.is_valid():
        form.save()
        return redirect("list")

    context = {"form": form}
    return render(request, "tasks/update_task.html", context)


@login_required
def deleteTask(request, pk):
    item = get_object_or_404(Task, id=pk, user=request.user)

    if request.method == "POST":
        item.delete()
        return redirect("list")

    context = {"item": item}
    return render(request, "tasks/delete.html", context)
