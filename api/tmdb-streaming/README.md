# Collection Bruno - TMDB Streaming Series

Cette collection contient 4 appels GET pour récupérer des séries TV via l'API TMDB.

## Prérequis

- Ouvrir le dossier `api/tmdb-streaming` dans Bruno.
- Sélectionner l'environnement `dev`.
- Renseigner `TMDB_READ_ACCESS_TOKEN` dans `environments/.env` (Read Access Token TMDB v4).
- Le même fichier `environments/.env` est utilisé aussi par l'application Django (`watch-list`) pour TMDB + FranceConnect.
- Pour tester FranceConnect en local, lancer Django sur le port `8000` (callback recommandé: `http://localhost:8000/callback`).
- Comptes FranceConnect mock (mot de passe `123`): `test`, `avec_nom_dusage`, `nom_composé`.

## Appels inclus

1. `GET 10 series Action & Adventure`
2. `GET 10 top-rated series on Netflix`
3. `GET 10 top-rated series on Amazon Prime Video`
4. `GET 10 top-rated series on Apple TV+`

## Notes importantes

- TMDB renvoie 20 résultats par page sur `discover/tv`. Pour obtenir vos 10 séries, prenez les 10 premières du tableau `results`.
- Les requêtes utilisent le header `Authorization: Bearer <token>` (pas de paramètre `api_key` dans l'URL).
- Les filtres plateformes utilisent `watch_region` (par défaut `US`).
- IDs providers utilisés:
  - Netflix: `8`
  - Amazon Prime Video: `9`
  - Apple TV+: `350`
- Si votre région diffère, ajuster `watch_region` (ex: `FR`, `US`, `CA`).
