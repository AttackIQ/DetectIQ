import environ
import os
from pathlib import Path
from pydantic import BaseModel, Field

from detectiq.core.config import config_manager
from detectiq.globals import DEFAULT_DIRS

# Initialize environment variables
env = environ.Env(
    DEBUG=(bool, False),
    DJANGO_SECRET_KEY=(str, "secretkey"),
    OPENAI_API_KEY=(str, ""),
)

# Base directory
BASE_DIR = DEFAULT_DIRS.BASE_DIR
DATA_DIR = DEFAULT_DIRS.DATA_DIR

# Ensure logs directory exists
log_dir = DATA_DIR / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

# Load environment variables from .env files - try multiple locations
for env_path in [BASE_DIR / ".env", DATA_DIR / ".env"]:
    if env_path.exists():
        env.read_env(env_path)

# Django settings
SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "django_extensions",
    "detectiq.webapp.backend",
    "detectiq.webapp.backend.rules.apps.RulesConfig",
    "detectiq.webapp.backend.app_config.apps.AppConfigConfig",
    "detectiq.webapp.backend.rule_creator.apps.RuleCreatorConfig",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "detectiq.webapp.backend.urls"
WSGI_APPLICATION = "detectiq.webapp.backend.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": DEFAULT_DIRS.DATA_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]

# Bridge DetectIQ settings to Django using globals
VECTOR_STORE_DIRS = {
    "sigma": DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR,
    "yara": DEFAULT_DIRS.YARA_VECTOR_STORE_DIR,
    "snort": DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR,
}

RULE_DIRS = {
    "sigma": DEFAULT_DIRS.SIGMA_RULE_DIR,
    "yara": DEFAULT_DIRS.YARA_RULE_DIR,
    "snort": DEFAULT_DIRS.SNORT_RULE_DIR,
}

# Django REST Framework settings (separate from DetectIQ settings)
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "EXCEPTION_HANDLER": "rest_framework.views.exception_handler",
    "FORMAT_SUFFIX_KWARG": "format",
    "VIEW_DESCRIPTION_FUNCTION": "rest_framework.views.get_view_description",
    "VIEW_NAME_FUNCTION": "rest_framework.views.get_view_name",
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Add this to your settings file
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": str(DATA_DIR / "logs/django-debug.log"),
            "level": "INFO",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": True,
        },
        "detectiq": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}

# Make sure DEBUG is True
DEBUG = True
