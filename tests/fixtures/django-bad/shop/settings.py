import sentry_sdk

DEBUG = True
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.auth", "rest_framework", "corsheaders", "shop"]
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
]
ROOT_URLCONF = "shop.urls"
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
CORS_ALLOW_ALL_ORIGINS = True
SESSION_COOKIE_SECURE = False

sentry_sdk.init(
    dsn="https://public@sentry.example.invalid/1",
    send_default_pii=True,
)
