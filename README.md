# Watch List (Django)

Application Django avec:
- authentification complète (inscription, connexion, déconnexion),
- reset password (forgot + reset token expiré et stocké hashé),
- watchlist privée par utilisateur,
- import de séries TMDB (Netflix / Amazon Prime / Apple TV) avec affiches.

## Prérequis

- Python 3.13+
- pipenv (ou pip + virtualenv)

## Variables d'environnement

Fichier partagé lu automatiquement:
- `api/tmdb-streaming/environments/.env`

- `DEBUG` (default: `true`)
- `ALLOWED_HOSTS` (default: `localhost,127.0.0.1`)
- `TMDB_READ_ACCESS_TOKEN`
- `TMDB_LANGUAGE` (default: `fr-FR`)
- `TMDB_WATCH_REGION` (default: `US`)
- `FRANCECONNECT_ENABLED` (default: `true`, actif seulement si client id/secret présents)
- `FRANCECONNECT_CLIENT_ID`
- `FRANCECONNECT_CLIENT_SECRET`
- `FRANCECONNECT_AUTHORIZE_URL` (default: `https://fcp-low.integ01.dev-franceconnect.fr/api/v2/authorize`)
- `FRANCECONNECT_TOKEN_URL` (default: `https://fcp-low.integ01.dev-franceconnect.fr/api/v2/token`)
- `FRANCECONNECT_USERINFO_URL` (default: `https://fcp-low.integ01.dev-franceconnect.fr/api/v2/userinfo`)
- `FRANCECONNECT_SCOPE` (default: `openid profile email`)
- `FRANCECONNECT_ACR_VALUES` (default: `eidas1`)
- `FRANCECONNECT_REDIRECT_URI` (optionnel, sinon auto-construit)
- `EMAIL_BACKEND` (default: `django.core.mail.backends.console.EmailBackend`)
- `DEFAULT_FROM_EMAIL` (default: `no-reply@watch-list.local`)
- `SESSION_COOKIE_SECURE` (default: `false`)
- `CSRF_COOKIE_SECURE` (default: `false`)
- `SECURE_HSTS_SECONDS` (default: `0`)
- `CORS_ALLOWED_ORIGINS` (comma-separated, example: `https://app.example.com`)

## Démarrage local

```bash
cd watch-list/watch-list
pipenv install
pipenv run python manage.py migrate
pipenv run python manage.py seed_data
pipenv run python manage.py runserver 8000
```

Utilisateurs:
- seed: `seed@example.com` / `SeedPass123!`

## Démarrage avec Docker

```bash
cd watch-list/watch-list
docker compose up --build
```

L'application est disponible sur `http://localhost:8000`.

Notes:
- Le conteneur exécute automatiquement `migrate` puis `seed_data` au démarrage.
- Les variables sont chargées depuis `api/tmdb-streaming/environments/.env` via `docker-compose.yml`.
- Le code est monté en volume (`.:/app`) pour le dev.

Commandes utiles:

```bash
# lancer les tests
docker compose run --rm web python manage.py test

# stopper les services
docker compose down
```

## Endpoints principaux

- `GET/POST /register/`
- `GET/POST /login/`
- `GET /login/franceconnect/` (démarrage OAuth2/OIDC FranceConnect)
- `GET /login/franceconnect/callback/` (callback OAuth2/OIDC FranceConnect)
- `POST /logout/`
- `GET/POST /forgot-password/`
- `GET/POST /reset-password/<token>/`
- `GET /me/` (JSON utilisateur connecté)
- `GET /` (watchlist privée, login requis)

## Sécurité implémentée

- Hash des mots de passe Django (`set_password` / auth backend Django)
- Validation serveur des formulaires
- Protection CSRF (sessions/cookies)
- Rate limiting:
  - `/login/`
  - `/forgot-password/`
- Messages neutres sur forgot-password (pas d'énumération d'email)
- Cookies session/CSRF durcis (`httpOnly`, `sameSite`, options `secure`)
- Headers sécurité + CORS restreint aux origines autorisées
- Pas de logs de mots de passe/tokens
- Tokens de reset stockés hashés + expiration + invalidation après usage

## Tests

```bash
cd watch-list/watch-list
python3 manage.py test
```

Les tests couvrent:
- validation formulaires auth,
- workflows register/login/logout/me,
- workflow login FranceConnect + création auto si utilisateur inconnu,
- forgot/reset password,
- isolation des watchlists par utilisateur,
- import TMDB et anti-doublons par utilisateur.

## FranceConnect local (dev)

- La config partagée est dans `api/tmdb-streaming/environments/.env`.
- Le callback recommandé en local est `http://localhost:8000/callback`.
- Comptes de dev (FranceConnect IDP mock) issus de:
  `https://github.com/france-connect/sources/blob/main/docker/volumes/fcp-low/mocks/idp/databases/citizen/base.csv`
- Exemples: `test / 123`, `avec_nom_dusage / 123`, `nom_composé / 123`.
