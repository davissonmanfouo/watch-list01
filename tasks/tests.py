import json
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse

from tasks.forms import RegisterForm, TaskForm
from tasks.models import PasswordResetToken, Task
from tasks.services.auth_service import get_valid_reset_token


User = get_user_model()


class ValidationTest(TestCase):
    def test_register_form_requires_valid_email(self):
        form = RegisterForm(
            data={
                "username": "alice",
                "email": "not-an-email",
                "password": "StrongPass123!",
                "password_confirm": "StrongPass123!",
                "accept_tos": True,
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_register_form_requires_password_confirmation(self):
        form = RegisterForm(
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "StrongPass123!",
                "password_confirm": "DifferentPass123!",
                "accept_tos": True,
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("password_confirm", form.errors)

    def test_register_form_requires_cgu_acceptance(self):
        form = RegisterForm(
            data={
                "username": "alice",
                "email": "alice@example.com",
                "password": "StrongPass123!",
                "password_confirm": "StrongPass123!",
                "accept_tos": False,
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("accept_tos", form.errors)

    def test_task_form_valid(self):
        form = TaskForm(data={"title": "Série à voir", "complete": False})
        self.assertTrue(form.is_valid())


class AuthFlowTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="john",
            email="john@example.com",
            password="SecurePass123!",
        )

    def _fake_oauth_response(self, payload):
        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        return FakeResponse(payload)

    def test_redirect_to_login_if_not_authenticated(self):
        response = self.client.get(reverse("list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/?next=/", response.url)

    def test_register_creates_account_and_logs_in(self):
        response = self.client.post(
            reverse("register"),
            data={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "StrongPass123!",
                "password_confirm": "StrongPass123!",
                "accept_tos": True,
            },
        )
        self.assertRedirects(response, reverse("list"))
        self.assertTrue(User.objects.filter(email="newuser@example.com").exists())

    def test_login_with_email_and_password(self):
        response = self.client.post(
            reverse("login"),
            data={"email": "john@example.com", "password": "SecurePass123!"},
        )
        self.assertRedirects(response, reverse("list"))

    def test_login_with_unverified_email_returns_specific_code(self):
        self.user.profile.email_verified = False
        self.user.profile.save(update_fields=["email_verified"])

        response = self.client.post(
            reverse("login"),
            data={"email": "john@example.com", "password": "SecurePass123!"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "EMAIL_NOT_VERIFIED", status_code=403)

    def test_login_rate_limited_after_too_many_attempts(self):
        cache.clear()
        for _ in range(8):
            self.client.post(
                reverse("login"),
                data={"email": "john@example.com", "password": "wrong-password"},
            )
        blocked = self.client.post(
            reverse("login"),
            data={"email": "john@example.com", "password": "wrong-password"},
        )
        self.assertEqual(blocked.status_code, 429)

    def test_logout_works(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("logout"))
        self.assertRedirects(response, reverse("login"))

    def test_me_endpoint_returns_authenticated_user(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["email"], "john@example.com")
        self.assertTrue(payload["authenticated"])

    def test_me_endpoint_returns_401_for_anonymous(self):
        response = self.client.get(reverse("me"))
        self.assertEqual(response.status_code, 401)

    @override_settings(FRANCECONNECT_ENABLED=True)
    def test_login_page_shows_franceconnect_button_when_enabled(self):
        response = self.client.get(reverse("login"))
        self.assertContains(response, "Se connecter avec FranceConnect")

    @override_settings(
        FRANCECONNECT_ENABLED=True,
        FRANCECONNECT_CLIENT_ID="client-id",
        FRANCECONNECT_CLIENT_SECRET="client-secret",
        FRANCECONNECT_AUTHORIZE_URL="https://fc.example/api/v2/authorize",
        FRANCECONNECT_ACR_VALUES="eidas1",
    )
    def test_franceconnect_login_redirects_to_authorization_endpoint(self):
        response = self.client.get(reverse("franceconnect_login"), {"next": reverse("list")})
        self.assertEqual(response.status_code, 302)

        parsed = urlparse(response.url)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "fc.example")
        self.assertEqual(parsed.path, "/api/v2/authorize")
        self.assertEqual(query["response_type"][0], "code")
        self.assertEqual(query["client_id"][0], "client-id")
        self.assertEqual(query["scope"][0], "openid profile email")
        self.assertEqual(query["acr_values"][0], "eidas1")
        self.assertIn("state", query)
        self.assertIn("nonce", query)
        self.assertEqual(query["redirect_uri"][0], "http://localhost:3000/callback")

        session = self.client.session
        self.assertEqual(session["franceconnect_oauth_state"], query["state"][0])
        self.assertEqual(session["franceconnect_oauth_next"], reverse("list"))
        self.assertEqual(session["franceconnect_oauth_nonce"], query["nonce"][0])

    @override_settings(
        FRANCECONNECT_ENABLED=True,
        FRANCECONNECT_CLIENT_ID="client-id",
        FRANCECONNECT_CLIENT_SECRET="client-secret",
        FRANCECONNECT_TOKEN_URL="https://fc.example/api/v2/token",
        FRANCECONNECT_USERINFO_URL="https://fc.example/api/v2/userinfo",
        FRANCECONNECT_REDIRECT_URI="http://testserver/login/franceconnect/callback/",
    )
    def test_franceconnect_callback_logs_in_existing_user(self):
        session = self.client.session
        session["franceconnect_oauth_state"] = "state-123"
        session["franceconnect_oauth_nonce"] = "nonce-123"
        session["franceconnect_oauth_next"] = reverse("list")
        session.save()

        def fake_urlopen(request, timeout=10):
            if request.full_url == "https://fc.example/api/v2/token":
                self.assertIn(b"code=auth-code", request.data)
                self.assertIn(b"nonce=nonce-123", request.data)
                return self._fake_oauth_response(
                    {"access_token": "token-123", "token_type": "Bearer"}
                )
            if request.full_url == "https://fc.example/api/v2/userinfo":
                return self._fake_oauth_response({"sub": "fc-sub-1", "email": "john@example.com"})
            raise AssertionError(f"Unexpected URL called: {request.full_url}")

        with patch("tasks.views.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                reverse("franceconnect_callback"),
                {"code": "auth-code", "state": "state-123"},
            )

        self.assertRedirects(response, reverse("list"))
        self.assertEqual(User.objects.filter(email="john@example.com").count(), 1)
        self.assertEqual(self.client.get(reverse("me")).json()["email"], "john@example.com")

    @override_settings(
        FRANCECONNECT_ENABLED=True,
        FRANCECONNECT_CLIENT_ID="client-id",
        FRANCECONNECT_CLIENT_SECRET="client-secret",
        FRANCECONNECT_TOKEN_URL="https://fc.example/api/v2/token",
        FRANCECONNECT_USERINFO_URL="https://fc.example/api/v2/userinfo",
        FRANCECONNECT_REDIRECT_URI="http://testserver/login/franceconnect/callback/",
    )
    def test_franceconnect_callback_creates_user_when_unknown(self):
        session = self.client.session
        session["franceconnect_oauth_state"] = "state-456"
        session["franceconnect_oauth_nonce"] = "nonce-456"
        session["franceconnect_oauth_next"] = reverse("list")
        session.save()

        def fake_urlopen(request, timeout=10):
            if request.full_url == "https://fc.example/api/v2/token":
                self.assertIn(b"nonce=nonce-456", request.data)
                return self._fake_oauth_response(
                    {"access_token": "token-456", "token_type": "Bearer"}
                )
            if request.full_url == "https://fc.example/api/v2/userinfo":
                return self._fake_oauth_response(
                    {
                        "sub": "fc-sub-2",
                        "email": "new-fc-user@example.com",
                        "given_name": "New",
                        "family_name": "User",
                    }
                )
            raise AssertionError(f"Unexpected URL called: {request.full_url}")

        with patch("tasks.views.urlopen", side_effect=fake_urlopen):
            response = self.client.get(
                reverse("franceconnect_callback"),
                {"code": "auth-code-2", "state": "state-456"},
            )

        self.assertRedirects(response, reverse("list"))
        created_user = User.objects.get(email="new-fc-user@example.com")
        self.assertEqual(created_user.first_name, "New")
        self.assertEqual(created_user.last_name, "User")
        self.assertFalse(created_user.has_usable_password())


class PasswordResetFlowTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="reset-user",
            email="reset@example.com",
            password="InitialPass123!",
        )

    def test_forgot_password_is_neutral_for_unknown_email(self):
        response = self.client.post(
            reverse("forgot_password"),
            data={"email": "unknown@example.com"},
            follow=True,
        )
        self.assertRedirects(response, reverse("login"))
        self.assertContains(
            response,
            "Si ce compte existe, un email de réinitialisation a été envoyé.",
        )
        self.assertEqual(PasswordResetToken.objects.count(), 0)

    def test_forgot_password_creates_hashed_token(self):
        response = self.client.post(
            reverse("forgot_password"),
            data={"email": "reset@example.com"},
        )
        self.assertRedirects(response, reverse("login"))
        token_obj = PasswordResetToken.objects.get(user=self.user)
        self.assertEqual(len(token_obj.token_hash), 64)

    def test_reset_password_updates_password(self):
        self.client.post(reverse("forgot_password"), data={"email": "reset@example.com"})
        token_obj = PasswordResetToken.objects.get(user=self.user)

        with patch("tasks.services.auth_service._hash_token") as hash_token_mock:
            hash_token_mock.return_value = token_obj.token_hash
            token_record = get_valid_reset_token("raw-token-value")
            self.assertIsNotNone(token_record)

            response = self.client.post(
                reverse("reset_password", kwargs={"token": "raw-token-value"}),
                data={
                    "password": "NewSecurePass123!",
                    "password_confirm": "NewSecurePass123!",
                },
            )

        self.assertRedirects(response, reverse("login"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewSecurePass123!"))
        token_obj.refresh_from_db()
        self.assertIsNotNone(token_obj.used_at)


class TaskIsolationTest(TestCase):
    def setUp(self):
        self.user_1 = User.objects.create_user(
            username="u1", email="u1@example.com", password="Pass12345!"
        )
        self.user_2 = User.objects.create_user(
            username="u2", email="u2@example.com", password="Pass12345!"
        )

    def test_list_shows_only_connected_user_tasks(self):
        Task.objects.create(title="Task U1", user=self.user_1)
        Task.objects.create(title="Task U2", user=self.user_2)

        self.client.force_login(self.user_1)
        response = self.client.get(reverse("list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Task U1")
        self.assertNotContains(response, "Task U2")

    def test_user_cannot_update_other_user_task(self):
        foreign_task = Task.objects.create(title="Task U2", user=self.user_2)
        self.client.force_login(self.user_1)
        response = self.client.get(reverse("update_task", kwargs={"pk": foreign_task.id}))
        self.assertEqual(response.status_code, 404)

    def test_user_cannot_delete_other_user_task(self):
        foreign_task = Task.objects.create(title="Task U2", user=self.user_2)
        self.client.force_login(self.user_1)
        response = self.client.get(reverse("delete", kwargs={"pk": foreign_task.id}))
        self.assertEqual(response.status_code, 404)


@override_settings(
    TMDB_READ_ACCESS_TOKEN="token",
    TMDB_LANGUAGE="fr-FR",
    TMDB_WATCH_REGION="US",
)
class WatchlistImportTest(TestCase):
    def setUp(self):
        self.user_1 = User.objects.create_user(
            username="u1", email="u1@example.com", password="Pass12345!"
        )
        self.user_2 = User.objects.create_user(
            username="u2", email="u2@example.com", password="Pass12345!"
        )

    def _fake_response(self, payload):
        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        return FakeResponse(payload)

    def test_add_watchlist_requires_authentication(self):
        response = self.client.post(
            reverse("add_watchlist_provider", kwargs={"provider_slug": "netflix"})
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/?next=", response.url)

    def test_add_netflix_watchlist_creates_10_items_for_connected_user(self):
        payload = {
            "results": [{"id": idx, "name": f"Serie {idx}"} for idx in range(1, 11)],
            "total_pages": 1,
        }
        self.client.force_login(self.user_1)
        with patch("tasks.views.urlopen") as mocked_urlopen:
            mocked_urlopen.return_value = self._fake_response(payload)
            response = self.client.post(
                reverse("add_watchlist_provider", kwargs={"provider_slug": "netflix"})
            )

        self.assertRedirects(response, reverse("list"))
        self.assertEqual(
            Task.objects.filter(user=self.user_1, provider_service_id="8").count(), 10
        )
        self.assertEqual(Task.objects.filter(user=self.user_2).count(), 0)

    def test_add_watchlist_saves_poster_and_renders_image(self):
        payload = {
            "results": [{"id": 42, "name": "Serie Imagee", "poster_path": "/poster-42.jpg"}],
            "total_pages": 1,
        }
        self.client.force_login(self.user_1)
        with patch("tasks.views.urlopen") as mocked_urlopen:
            mocked_urlopen.return_value = self._fake_response(payload)
            response = self.client.post(
                reverse("add_watchlist_provider", kwargs={"provider_slug": "netflix"})
            )

        self.assertRedirects(response, reverse("list"))
        task = Task.objects.get(user=self.user_1, tmdb_series_id=42)
        self.assertEqual(task.poster_path, "/poster-42.jpg")

        list_response = self.client.get(reverse("list"))
        self.assertContains(list_response, "https://image.tmdb.org/t/p/w342/poster-42.jpg")

    def test_double_click_netflix_adds_20_distinct_series_for_same_user(self):
        self.client.force_login(self.user_1)

        def fake_urlopen(request, timeout=10):
            parsed = urlparse(request.full_url)
            page = int(parse_qs(parsed.query).get("page", ["1"])[0])
            if page == 1:
                payload = {
                    "results": [
                        {"id": idx, "name": f"Netflix Serie {idx}"} for idx in range(1, 11)
                    ],
                    "total_pages": 2,
                }
            else:
                payload = {
                    "results": [
                        {"id": idx, "name": f"Netflix Serie {idx}"} for idx in range(11, 21)
                    ],
                    "total_pages": 2,
                }
            return self._fake_response(payload)

        with patch("tasks.views.urlopen", side_effect=fake_urlopen):
            first = self.client.post(
                reverse("add_watchlist_provider", kwargs={"provider_slug": "netflix"})
            )
            second = self.client.post(
                reverse("add_watchlist_provider", kwargs={"provider_slug": "netflix"})
            )

        self.assertRedirects(first, reverse("list"))
        self.assertRedirects(second, reverse("list"))
        self.assertEqual(
            Task.objects.filter(user=self.user_1, provider_service_id="8").count(), 20
        )
        self.assertEqual(
            Task.objects.filter(user=self.user_1, provider_service_id="8")
            .values("tmdb_series_id")
            .distinct()
            .count(),
            20,
        )
