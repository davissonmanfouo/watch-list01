from functools import wraps

from django.core.cache import cache
from django.http import HttpResponse


def _get_client_ip(request):
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _rate_limit_key(scope, request):
    return f"rate-limit:{scope}:{_get_client_ip(request)}"


def clear_rate_limit(scope, request):
    cache.delete(_rate_limit_key(scope, request))


def rate_limit(scope, limit=5, window_seconds=900):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if request.method != "POST":
                return view_func(request, *args, **kwargs)

            key = _rate_limit_key(scope, request)
            count = cache.get(key, 0)
            if count >= limit:
                return HttpResponse(
                    "Trop de tentatives. Réessayez plus tard.",
                    status=429,
                )

            cache.set(key, count + 1, timeout=window_seconds)
            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator
