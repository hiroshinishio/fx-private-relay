"""
Django settings for privaterelay project.

Generated by 'django-admin startproject' using Django 2.2.2.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

from __future__ import annotations
import ipaddress
import os, sys
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING


from decouple import config, Choices, Csv
import django_stubs_ext
import markus
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.logging import ignore_logger
from hashlib import sha512
import base64

from django.conf.global_settings import LANGUAGES as DEFAULT_LANGUAGES

import dj_database_url

if TYPE_CHECKING:
    import wsgiref.headers

try:
    # Silk is a live profiling and inspection tool for the Django framework
    # https://github.com/jazzband/django-silk
    import silk

    HAS_SILK = True
except ImportError:
    HAS_SILK = False

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_DIR = os.path.join(BASE_DIR, "tmp")
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# defaulting to blank to be production-broken by default
SECRET_KEY = config("SECRET_KEY", None, cast=str)
SITE_ORIGIN = config("SITE_ORIGIN", None)

ORIGIN_CHANNEL_MAP: dict[Optional[str], str] = {
    "http://127.0.0.1:8000": "local",
    "https://dev.fxprivaterelay.nonprod.cloudops.mozgcp.net": "dev",
    "https://stage.fxprivaterelay.nonprod.cloudops.mozgcp.net": "stage",
    "https://relay.firefox.com": "prod",
}
_DEFAULT_RELAY_CHANNEL = ORIGIN_CHANNEL_MAP.get(SITE_ORIGIN, "local")
RELAY_CHANNEL = config("RELAY_CHANNEL", default=_DEFAULT_RELAY_CHANNEL)

DEBUG = config("DEBUG", False, cast=bool)
if DEBUG:
    INTERNAL_IPS = config("DJANGO_INTERNAL_IPS", default="", cast=Csv())
IN_PYTEST = "pytest" in sys.modules
USE_SILK = DEBUG and HAS_SILK and not IN_PYTEST

# Honor the 'X-Forwarded-Proto' header for request.is_secure()
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_HOST = config("DJANGO_SECURE_SSL_HOST", None)
SECURE_SSL_REDIRECT = config("DJANGO_SECURE_SSL_REDIRECT", False)
SECURE_REDIRECT_EXEMPT = [
    r"^__version__",
    r"^__heartbeat__",
    r"^__lbheartbeat__",
]
SECURE_HSTS_SECONDS = config("DJANGO_SECURE_HSTS_SECONDS", None)
SECURE_BROWSER_XSS_FILTER = config("DJANGO_SECURE_BROWSER_XSS_FILTER", True)
SESSION_COOKIE_SECURE = config("DJANGO_SESSION_COOKIE_SECURE", False, cast=bool)
BASKET_ORIGIN = config("BASKET_ORIGIN", "https://basket.mozilla.org")
# maps fxa profile hosts to respective avatar hosts for CSP
AVATAR_IMG_SRC_MAP = {
    "https://profile.stage.mozaws.net/v1": [
        "mozillausercontent.com",
        "https://profile.stage.mozaws.net",
    ],
    "https://profile.accounts.firefox.com/v1": [
        "firefoxusercontent.com",
        "https://profile.accounts.firefox.com",
    ],
}
AVATAR_IMG_SRC = AVATAR_IMG_SRC_MAP[
    config("FXA_PROFILE_ENDPOINT", "https://profile.accounts.firefox.com/v1")
]
CSP_CONNECT_SRC = (
    "'self'",
    "https://www.google-analytics.com/",
    "https://accounts.firefox.com",
    "https://location.services.mozilla.com",
    BASKET_ORIGIN,
)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = [
    "'self'",
    "https://www.google-analytics.com/",
]
if USE_SILK:
    CSP_SCRIPT_SRC.append("'unsafe-inline'")

csp_style_values = ["'self'"]
# Next.js dynamically inserts the relevant styles when switching pages,
# by injecting them as inline styles. We need to explicitly allow those styles
# in our Content Security Policy.
if RELAY_CHANNEL == "local":
    # When running locally, styles might get refreshed while the server is
    # running, so their hashes would get oudated. Hence, we just allow all of
    # them.
    csp_style_values.append("'unsafe-inline'")
else:
    # When running in production, we want to disallow inline styles that are
    # not set by us, so we use an explicit allowlist with the hashes of the
    # styles generated by Next.js.
    _next_css_path = os.path.join(STATIC_ROOT, "_next", "static", "css")
    for root, dirs, files in os.walk(_next_css_path):
        for name in files:
            if name.endswith("css"):
                file_name = os.path.join(root, name)
                hasher = sha512()
                with open(str(file_name), "rb") as f:
                    while True:
                        data = f.read()
                        if not data:
                            break
                        hasher.update(data)
                hash = base64.b64encode(hasher.digest()).decode("utf-8")
                csp_style_values.append("'sha512-%s'" % hash)

CSP_STYLE_SRC = tuple(csp_style_values)

CSP_IMG_SRC = ["'self'"] + AVATAR_IMG_SRC
REFERRER_POLICY = "strict-origin-when-cross-origin"

ALLOWED_HOSTS = []
DJANGO_ALLOWED_HOSTS = config("DJANGO_ALLOWED_HOST", "", cast=Csv())
if DJANGO_ALLOWED_HOSTS:
    ALLOWED_HOSTS += DJANGO_ALLOWED_HOSTS
DJANGO_ALLOWED_SUBNET = config("DJANGO_ALLOWED_SUBNET", None)
if DJANGO_ALLOWED_SUBNET:
    ALLOWED_HOSTS += [str(ip) for ip in ipaddress.IPv4Network(DJANGO_ALLOWED_SUBNET)]


# Get our backing resource configs to check if we should install the app
ADMIN_ENABLED = config("ADMIN_ENABLED", False, cast=bool)


AWS_REGION = config("AWS_REGION", None)
AWS_ACCESS_KEY_ID = config("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = config("AWS_SECRET_ACCESS_KEY", None)
AWS_SNS_TOPIC = set(config("AWS_SNS_TOPIC", "", cast=Csv()))
AWS_SNS_KEY_CACHE = config("AWS_SNS_KEY_CACHE", "default")
AWS_SES_CONFIGSET = config("AWS_SES_CONFIGSET", None)
AWS_SQS_EMAIL_QUEUE_URL = config("AWS_SQS_EMAIL_QUEUE_URL", None)
AWS_SQS_EMAIL_DLQ_URL = config("AWS_SQS_EMAIL_DLQ_URL", None)

# Dead-Letter Queue (DLQ) for SNS push subscription
AWS_SQS_QUEUE_URL = config("AWS_SQS_QUEUE_URL", None)

RELAY_FROM_ADDRESS = config("RELAY_FROM_ADDRESS", None)
NEW_RELAY_FROM_ADDRESS = config("NEW_RELAY_FROM_ADDRESS")
GOOGLE_ANALYTICS_ID = config("GOOGLE_ANALYTICS_ID", None)
INCLUDE_VPN_BANNER = config("INCLUDE_VPN_BANNER", False, cast=bool)
RECRUITMENT_BANNER_LINK = config("RECRUITMENT_BANNER_LINK", None)
RECRUITMENT_BANNER_TEXT = config("RECRUITMENT_BANNER_TEXT", None)
RECRUITMENT_EMAIL_BANNER_TEXT = config("RECRUITMENT_EMAIL_BANNER_TEXT", None)
RECRUITMENT_EMAIL_BANNER_LINK = config("RECRUITMENT_EMAIL_BANNER_LINK", None)

PHONES_ENABLED = config("PHONES_ENABLED", False, cast=bool)
TWILIO_ACCOUNT_SID = config("TWILIO_ACCOUNT_SID", None)
TWILIO_AUTH_TOKEN = config("TWILIO_AUTH_TOKEN", None)
TWILIO_MAIN_NUMBER = config("TWILIO_MAIN_NUMBER", None)
TWILIO_SMS_APPLICATION_SID = config("TWILIO_SMS_APPLICATION_SID", None)
TWILIO_MESSAGING_SERVICE_SID = config("TWILIO_MESSAGING_SERVICE_SID", None)
TWILIO_TEST_ACCOUNT_SID = config("TWILIO_TEST_ACCOUNT_SID", None)
TWILIO_TEST_AUTH_TOKEN = config("TWILIO_TEST_AUTH_TOKEN", None)
TWILIO_ALLOWED_COUNTRY_CODES = set(
    code.upper() for code in config("TWILIO_ALLOWED_COUNTRY_CODES", "US,CA", cast=Csv())
)
MAX_MINUTES_TO_VERIFY_REAL_PHONE = config(
    "MAX_MINUTES_TO_VERIFY_REAL_PHONE", 5, cast=int
)
MAX_TEXTS_PER_BILLING_CYCLE = config("MAX_TEXTS_PER_BILLING_CYCLE", 75, cast=int)
MAX_MINUTES_PER_BILLING_CYCLE = config("MAX_MINUTES_PER_BILLING_CYCLE", 50, cast=int)
DAYS_PER_BILLING_CYCLE = config("DAYS_PER_BILLING_CYCLE", 30, cast=int)

DJANGO_STATSD_ENABLED = config("DJANGO_STATSD_ENABLED", False, cast=bool)
STATSD_DEBUG = config("STATSD_DEBUG", False, cast=bool)
STATSD_ENABLED = DJANGO_STATSD_ENABLED or STATSD_DEBUG
STATSD_HOST = config("DJANGO_STATSD_HOST", "127.0.0.1")
STATSD_PORT = config("DJANGO_STATSD_PORT", "8125")
STATSD_PREFIX = config("DJANGO_STATSD_PREFIX", "fx.private.relay")

SERVE_ADDON = config("SERVE_ADDON", None)

# Application definition
INSTALLED_APPS = [
    "whitenoise.runserver_nostatic",
    "django.contrib.staticfiles",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.sites",
    "django_filters",
    "django_ftl.apps.DjangoFtlConfig",
    "dockerflow.django",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.fxa",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "waffle",
    "privaterelay.apps.PrivateRelayConfig",
    "api.apps.ApiConfig",
]

API_DOCS_ENABLED = config("API_DOCS_ENABLED", False, cast=bool) or DEBUG
if API_DOCS_ENABLED:
    INSTALLED_APPS += [
        "drf_yasg",
    ]

if DEBUG:
    INSTALLED_APPS += [
        "debug_toolbar",
    ]

if USE_SILK:
    INSTALLED_APPS.append("silk")

if ADMIN_ENABLED:
    INSTALLED_APPS += [
        "django.contrib.admin",
    ]

if AWS_SES_CONFIGSET and AWS_SNS_TOPIC:
    INSTALLED_APPS += [
        "emails.apps.EmailsConfig",
    ]

if PHONES_ENABLED:
    INSTALLED_APPS += [
        "phones.apps.PhonesConfig",
    ]


# statsd middleware has to be first to catch errors in everything else
def _get_initial_middleware() -> list[str]:
    if STATSD_ENABLED:
        return [
            "privaterelay.middleware.ResponseMetrics",
        ]
    return []


MIDDLEWARE = _get_initial_middleware()

if USE_SILK:
    MIDDLEWARE.append("silk.middleware.SilkyMiddleware")
if DEBUG:
    MIDDLEWARE.append("debug_toolbar.middleware.DebugToolbarMiddleware")

MIDDLEWARE += [
    "django.middleware.security.SecurityMiddleware",
    "csp.middleware.CSPMiddleware",
    "privaterelay.middleware.RedirectRootIfLoggedIn",
    "privaterelay.middleware.RelayStaticFilesMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django_ftl.middleware.activate_from_request_language_code",
    "django_referrer_policy.middleware.ReferrerPolicyMiddleware",
    "dockerflow.django.middleware.DockerflowMiddleware",
    "waffle.middleware.WaffleMiddleware",
    "privaterelay.middleware.FxAToRequest",
    "privaterelay.middleware.AddDetectedCountryToRequestAndResponseHeaders",
    "privaterelay.middleware.StoreFirstVisit",
]

ROOT_URLCONF = "privaterelay.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            os.path.join(BASE_DIR, "privaterelay", "templates"),
        ],
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

RELAY_FIREFOX_DOMAIN = config("RELAY_FIREFOX_DOMAIN", "relay.firefox.com", cast=str)
MOZMAIL_DOMAIN = config("MOZMAIL_DOMAIN", "mozmail.com", cast=str)
MAX_NUM_FREE_ALIASES = config("MAX_NUM_FREE_ALIASES", 5, cast=int)
PERIODICAL_PREMIUM_PROD_ID = config("PERIODICAL_PREMIUM_PROD_ID", "", cast=str)
PREMIUM_PLAN_ID_US_MONTHLY = config(
    "PREMIUM_PLAN_ID_US_MONTHLY", "price_1LXUcnJNcmPzuWtRpbNOajYS", cast=str
)
PREMIUM_PLAN_ID_US_YEARLY = config(
    "PREMIUM_PLAN_ID_US_YEARLY", "price_1LXUdlJNcmPzuWtRKTYg7mpZ", cast=str
)
PHONE_PROD_ID = config("PHONE_PROD_ID", "", cast=str)
PHONE_PLAN_ID_US_MONTHLY = config(
    "PHONE_PLAN_ID_US_MONTHLY", "price_1Li0w8JNcmPzuWtR2rGU80P3", cast=str
)
PHONE_PLAN_ID_US_YEARLY = config(
    "PHONE_PLAN_ID_US_YEARLY", "price_1Li15WJNcmPzuWtRIh0F4VwP", cast=str
)
BUNDLE_PROD_ID = config("BUNDLE_PROD_ID", "", cast=str)
BUNDLE_PLAN_ID_US = config(
    "BUNDLE_PLAN_ID_US", "price_1LwoSDJNcmPzuWtR6wPJZeoh", cast=str
)

PERIODICAL_PREMIUM_PLAN_ID_MATRIX = {
    "chf": {
        "de": {
            "monthly": {
                "id": "price_1LYCqOJNcmPzuWtRuIXpQRxi",
                "price": 2.00,
                "currency": "CHF",
            },
            "yearly": {
                "id": "price_1LYCqyJNcmPzuWtR3Um5qDPu",
                "price": 1.00,
                "currency": "CHF",
            },
        },
        "fr": {
            "monthly": {
                "id": "price_1LYCvpJNcmPzuWtRq9ci2gXi",
                "price": 2.00,
                "currency": "CHF",
            },
            "yearly": {
                "id": "price_1LYCwMJNcmPzuWtRm6ebmq2N",
                "price": 1.00,
                "currency": "CHF",
            },
        },
        "it": {
            "monthly": {
                "id": "price_1LYCiBJNcmPzuWtRxtI8D5Uy",
                "price": 2.00,
                "currency": "CHF",
            },
            "yearly": {
                "id": "price_1LYClxJNcmPzuWtRWjslDdkG",
                "price": 1.00,
                "currency": "CHF",
            },
        },
    },
    "euro": {
        "de": {
            "monthly": {
                "id": "price_1LYC79JNcmPzuWtRU7Q238yL",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYC7xJNcmPzuWtRcdKXCVZp",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "es": {
            "monthly": {
                "id": "price_1LYCWmJNcmPzuWtRtopZog9E",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYCXNJNcmPzuWtRu586XOFf",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "fr": {
            "monthly": {
                "id": "price_1LYBuLJNcmPzuWtRn58XQcky",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYBwcJNcmPzuWtRpgoWcb03",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "it": {
            "monthly": {
                "id": "price_1LYCMrJNcmPzuWtRTP9vD8wY",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYCN2JNcmPzuWtRtWz7yMno",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "nl": {
            "monthly": {
                "id": "price_1LYCdLJNcmPzuWtR0J1EHoJ0",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYCdtJNcmPzuWtRVm4jLzq2",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "ie": {
            "monthly": {
                "id": "price_1LhdrkJNcmPzuWtRvCc4hsI2",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LhdprJNcmPzuWtR7HqzkXTS",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "se": {
            "monthly": {
                "id": "price_1LYBblJNcmPzuWtRGRHIoYZ5",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYBeMJNcmPzuWtRT5A931WH",
                "price": 0.99,
                "currency": "EUR",
            },
        },
        "fi": {
            "monthly": {
                "id": "price_1LYBn9JNcmPzuWtRI3nvHgMi",
                "price": 1.99,
                "currency": "EUR",
            },
            "yearly": {
                "id": "price_1LYBq1JNcmPzuWtRmyEa08Wv",
                "price": 0.99,
                "currency": "EUR",
            },
        },
    },
    "usd": {
        "en": {
            "monthly": {
                "id": PREMIUM_PLAN_ID_US_MONTHLY,
                "price": 1.99,
                "currency": "USD",
            },
            "yearly": {
                "id": PREMIUM_PLAN_ID_US_YEARLY,
                "price": 0.99,
                "currency": "USD",
            },
        },
        "gb": {
            "monthly": {
                "id": "price_1LYCHpJNcmPzuWtRhrhSYOKB",
                "price": 1.99,
                "currency": "USD",
            },
            "yearly": {
                "id": "price_1LYCIlJNcmPzuWtRQtYLA92j",
                "price": 0.99,
                "currency": "USD",
            },
        },
    },
}
PERIODICAL_PREMIUM_PLAN_COUNTRY_LANG_MAPPING = {
    # Austria
    "at": {
        "de": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["de"],
    },
    # Belgium
    "be": {
        "fr": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["fr"],
        "de": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["de"],
        "nl": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["nl"],
    },
    # Switzerland
    "ch": {
        "fr": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["chf"]["fr"],
        "de": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["chf"]["de"],
        "it": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["chf"]["it"],
    },
    # Germany
    "de": {
        "de": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["de"],
    },
    # Spain
    "es": {
        "es": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["es"],
    },
    # France
    "fr": {
        "fr": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["fr"],
    },
    # Ireland
    "ie": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["ie"],
    },
    # Italy
    "it": {
        "it": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["it"],
    },
    # Netherlands
    "nl": {
        "nl": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["nl"],
    },
    # Sweden
    "se": {
        "sv": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["se"],
    },
    # Finland
    "fi": {
        "fi": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["euro"]["fi"],
    },
    "us": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["en"],
    },
    "gb": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["gb"],
    },
    "ca": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["en"],
    },
    "nz": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["gb"],
    },
    "my": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["gb"],
    },
    "sg": {
        "en": PERIODICAL_PREMIUM_PLAN_ID_MATRIX["usd"]["gb"],
    },
}

PHONE_PLAN_ID_MATRIX = {
    "usd": {
        "en": {
            "monthly": {
                "id": PHONE_PLAN_ID_US_MONTHLY,
                "price": 4.99,
                "currency": "USD",
            },
            "yearly": {
                "id": PHONE_PLAN_ID_US_YEARLY,
                "price": 3.99,
                "currency": "USD",
            },
        },
    },
}
PHONE_PLAN_COUNTRY_LANG_MAPPING = {
    "us": {
        "en": PHONE_PLAN_ID_MATRIX["usd"]["en"],
    },
    "ca": {
        "en": PHONE_PLAN_ID_MATRIX["usd"]["en"],
    },
}

BUNDLE_PLAN_ID_MATRIX = {
    "usd": {
        "en": {
            "yearly": {
                # To allow testing the subscription flow on stage, we can set
                # a custom plan ID via an environment variable:
                "id": BUNDLE_PLAN_ID_US,
                "price": 6.99,
                "currency": "USD",
            },
        },
    },
}
BUNDLE_PLAN_COUNTRY_LANG_MAPPING = {
    "us": {
        "en": BUNDLE_PLAN_ID_MATRIX["usd"]["en"],
    },
    "ca": {
        "en": BUNDLE_PLAN_ID_MATRIX["usd"]["en"],
    },
}

SUBSCRIPTIONS_WITH_UNLIMITED = config(
    "SUBSCRIPTIONS_WITH_UNLIMITED", default="", cast=Csv()
)
SUBSCRIPTIONS_WITH_PHONE = config("SUBSCRIPTIONS_WITH_PHONE", default="", cast=Csv())
SUBSCRIPTIONS_WITH_VPN = config("SUBSCRIPTIONS_WITH_VPN", default="", cast=Csv())

MAX_ONBOARDING_AVAILABLE = config("MAX_ONBOARDING_AVAILABLE", 0, cast=int)

MAX_ADDRESS_CREATION_PER_DAY = config("MAX_ADDRESS_CREATION_PER_DAY", 100, cast=int)
MAX_REPLIES_PER_DAY = config("MAX_REPLIES_PER_DAY", 100, cast=int)
MAX_FORWARDED_PER_DAY = config("MAX_FORWARDED_PER_DAY", 1000, cast=int)
MAX_FORWARDED_EMAIL_SIZE_PER_DAY = config(
    "MAX_FORWARDED_EMAIL_SIZE_PER_DAY", 1_000_000_000, cast=int
)
PREMIUM_FEATURE_PAUSED_DAYS = config("ACCOUNT_PREMIUM_FEATURE_PAUSED_DAYS", 1, cast=int)

SOFT_BOUNCE_ALLOWED_DAYS = config("SOFT_BOUNCE_ALLOWED_DAYS", 1, cast=int)
HARD_BOUNCE_ALLOWED_DAYS = config("HARD_BOUNCE_ALLOWED_DAYS", 30, cast=int)

WSGI_APPLICATION = "privaterelay.wsgi.application"

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    "default": dj_database_url.config(
        default="sqlite:///%s" % os.path.join(BASE_DIR, "db.sqlite3")
    )
}

REDIS_URL = config("REDIS_URL", "", cast=str)
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
        }
    }
    SESSION_ENGINE = "django.contrib.sessions.backends.cache"
    SESSION_CACHE_ALIAS = "default"

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
# only needed when admin UI is enabled
if ADMIN_ENABLED:
    AUTH_PASSWORD_VALIDATORS = [
        {
            "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
        },
    ]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = "en"

# Mozilla l10n directories use lang-locale language codes,
# so we need to add those to LANGUAGES so Django's LocaleMiddleware
# can find them.
LANGUAGES = DEFAULT_LANGUAGES + [
    ("zh-tw", "Chinese"),
    ("zh-cn", "Chinese"),
]

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "frontend/out"),
]
# Static files (the front-end in /frontend/)
# https://whitenoise.evans.io/en/stable/django.html#using-whitenoise-with-webpack-browserify-latest-js-thing
STATIC_URL = "/"
if DEBUG:
    # In production, we run collectstatic to index all static files.
    # However, when running locally, we want to automatically pick up
    # all files spewed out by `npm run watch` in /frontend/out,
    # and we're fine with the performance impact of that.
    WHITENOISE_ROOT = os.path.join(BASE_DIR, "frontend/out")
STATICFILES_STORAGE = "privaterelay.storage.RelayStaticFilesStorage"

# Relay does not support user-uploaded files
MEDIA_ROOT = None
MEDIA_URL = None

WHITENOISE_INDEX_FILE = True

# See
# https://whitenoise.evans.io/en/stable/django.html#WHITENOISE_ADD_HEADERS_FUNCTION
# Intended to ensure that the homepage does not get cached in our CDN,
# so that the `RedirectRootIfLoggedIn` middleware can kick in for logged-in
# users.
def set_index_cache_control_headers(
    headers: wsgiref.headers.Headers, path: str, url: str
) -> None:
    if DEBUG:
        home_path = os.path.join(BASE_DIR, "frontend/out", "index.html")
    else:
        home_path = os.path.join(STATIC_ROOT, "index.html")
    if path == home_path:
        headers["Cache-Control"] = "no-cache, public"


WHITENOISE_ADD_HEADERS_FUNCTION = set_index_cache_control_headers

SITE_ID = 1

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
)

SOCIALACCOUNT_PROVIDERS = {
    "fxa": {
        # Note: to request "profile" scope, must be a trusted Mozilla client
        "SCOPE": ["profile"],
        "AUTH_PARAMS": {"access_type": "offline"},
        "OAUTH_ENDPOINT": config(
            "FXA_OAUTH_ENDPOINT", "https://oauth.accounts.firefox.com/v1"
        ),
        "PROFILE_ENDPOINT": config(
            "FXA_PROFILE_ENDPOINT", "https://profile.accounts.firefox.com/v1"
        ),
    }
}

SOCIALACCOUNT_EMAIL_VERIFICATION = "none"
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_PRESERVE_USERNAME_CASING = False
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_LOGIN_ON_GET = True
SOCIALACCOUNT_STORE_TOKENS = True

FXA_BASE_ORIGIN = config("FXA_BASE_ORIGIN", "https://accounts.firefox.com")
FXA_SETTINGS_URL = config("FXA_SETTINGS_URL", f"{FXA_BASE_ORIGIN}/settings")
FXA_SUBSCRIPTIONS_URL = config(
    "FXA_SUBSCRIPTIONS_URL", f"{FXA_BASE_ORIGIN}/subscriptions"
)
FXA_SUPPORT_URL = config("FXA_SUPPORT_URL", f"{FXA_BASE_ORIGIN}/support/")

LOGGING = {
    "version": 1,
    "formatters": {
        "json": {
            "()": "dockerflow.logging.JsonLogFormatter",
            "logger_name": "fx-private-relay",
        }
    },
    "handlers": {
        "console_out": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "stream": sys.stdout,
            "formatter": "json",
        },
        "console_err": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "loggers": {
        "request.summary": {
            "handlers": ["console_out"],
            "level": "DEBUG",
        },
        "events": {
            "handlers": ["console_err"],
            "level": "ERROR",
        },
        "eventsinfo": {
            "handlers": ["console_out"],
            "level": "INFO",
        },
        "abusemetrics": {"handlers": ["console_out"], "level": "INFO"},
        "studymetrics": {"handlers": ["console_out"], "level": "INFO"},
        "markus": {"handlers": ["console_out"], "level": "DEBUG"},
    },
}

DRF_RENDERERS = ["rest_framework.renderers.JSONRenderer"]
if DEBUG and not IN_PYTEST:
    DRF_RENDERERS += [
        "rest_framework.renderers.BrowsableAPIRenderer",
    ]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "api.authentication.FxaTokenAuthentication",
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": DRF_RENDERERS,
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "EXCEPTION_HANDLER": "api.views.relay_exception_handler",
}

PHONE_RATE_LIMIT = "5/minute"
if IN_PYTEST or RELAY_CHANNEL in ["local", "dev"]:
    PHONE_RATE_LIMIT = "1000/minute"

# Turn on logging out on GET in development.
# This allows `/mock/logout/` in the front-end to clear the
# session cookie. Without this, after switching accounts in dev mode,
# then logging out again, API requests continue succeeding even without
# an auth token:
ACCOUNT_LOGOUT_ON_GET = DEBUG

CORS_URLS_REGEX = r"^/api/"
CORS_ALLOWED_ORIGINS = [
    "https://vault.bitwarden.com",
]
if RELAY_CHANNEL in ["dev", "stage"]:
    CORS_ALLOWED_ORIGINS += ["https://vault.qa.bitwarden.pw"]
if RELAY_CHANNEL == "local":
    # In local dev, next runs on localhost and makes requests to /accounts/
    CORS_ALLOWED_ORIGINS += ["http://localhost:3000"]
    CORS_URLS_REGEX = r"^/(api|accounts)/"

CSRF_TRUSTED_ORIGINS = []
if RELAY_CHANNEL == "local":
    # In local development, the React UI can be served up from a different server
    # that needs to be allowed to make requests.
    # In production, the frontend is served by Django, is therefore on the same
    # origin and thus has access to the same cookies.
    CORS_ALLOW_CREDENTIALS = True
    SESSION_COOKIE_SAMESITE = None
    CORS_ALLOWED_ORIGINS += [
        "http://localhost:3000",
        "http://0.0.0.0:3000",
    ]
    CSRF_TRUSTED_ORIGINS += [
        "http://localhost:3000",
        "http://0.0.0.0:3000",
    ]

SENTRY_RELEASE = config("SENTRY_RELEASE", "")
CIRCLE_SHA1 = config("CIRCLE_SHA1", "")
CIRCLE_TAG = config("CIRCLE_TAG", "")
CIRCLE_BRANCH = config("CIRCLE_BRANCH", "")

sentry_release: Optional[str] = None
if SENTRY_RELEASE:
    sentry_release = SENTRY_RELEASE
elif CIRCLE_TAG and CIRCLE_TAG != "unknown":
    sentry_release = CIRCLE_TAG
elif (
    CIRCLE_SHA1
    and CIRCLE_SHA1 != "unknown"
    and CIRCLE_BRANCH
    and CIRCLE_BRANCH != "unknown"
):
    sentry_release = f"{CIRCLE_BRANCH}:{CIRCLE_SHA1}"

SENTRY_DEBUG = config("SENTRY_DEBUG", DEBUG, cast=bool)

SENTRY_ENVIRONMENT = config("SENTRY_ENVIRONMENT", RELAY_CHANNEL)
# Use "local" as default rather than "prod", to catch ngrok.io URLs
if SENTRY_ENVIRONMENT == "prod" and SITE_ORIGIN != "https://relay.firefox.com":
    SENTRY_ENVIRONMENT = "local"

sentry_sdk.init(
    dsn=config("SENTRY_DSN", None),
    integrations=[DjangoIntegration()],
    debug=SENTRY_DEBUG,
    with_locals=DEBUG,
    release=sentry_release,
    environment=SENTRY_ENVIRONMENT,
)
# Duplicates events for unhandled exceptions, but without useful tracebacks
ignore_logger("request.summary")
# Security scanner attempts, no action required
# Can be re-enabled when hostname allow list implemented at the load balancer
ignore_logger("django.security.DisallowedHost")
# Fluent errors, mostly when a translation is unavailable for the locale.
# It is more effective to process these from logs using BigQuery than to track
# as events in Sentry.
ignore_logger("django_ftl.message_errors")
# Security scanner attempts on Heroku dev, no action required
if RELAY_CHANNEL == "dev":
    ignore_logger("django.security.SuspiciousFileOperation")


_MARKUS_BACKENDS: list[dict[str, Any]] = []
if DJANGO_STATSD_ENABLED:
    _MARKUS_BACKENDS.append(
        {
            "class": "markus.backends.datadog.DatadogMetrics",
            "options": {
                "statsd_host": STATSD_HOST,
                "statsd_port": STATSD_PORT,
                "statsd_prefix": STATSD_PREFIX,
            },
        }
    )
if STATSD_DEBUG:
    _MARKUS_BACKENDS.append(
        {
            "class": "markus.backends.logging.LoggingMetrics",
            "options": {
                "logger_name": "markus",
                "leader": "METRICS",
            },
        }
    )
markus.configure(backends=_MARKUS_BACKENDS)

if USE_SILK:
    SILKY_PYTHON_PROFILER = True
    SILKY_PYTHON_PROFILER_BINARY = True

# Settings for manage.py process_emails_from_sqs
PROCESS_EMAIL_BATCH_SIZE = config(
    "PROCESS_EMAIL_BATCH_SIZE", 10, cast=Choices(range(1, 11), cast=int)
)
PROCESS_EMAIL_DELETE_FAILED_MESSAGES = config(
    "PROCESS_EMAIL_DELETE_FAILED_MESSAGES", False, cast=bool
)
PROCESS_EMAIL_HEALTHCHECK_PATH = config(
    "PROCESS_EMAIL_HEALTHCHECK_PATH", os.path.join(TMP_DIR, "healthcheck.json")
)
PROCESS_EMAIL_MAX_SECONDS = config("PROCESS_EMAIL_MAX_SECONDS", 0, cast=int) or None
PROCESS_EMAIL_VERBOSITY = config(
    "PROCESS_EMAIL_VERBOSITY", 1, cast=Choices(range(0, 4), cast=int)
)
PROCESS_EMAIL_VISIBILITY_SECONDS = config(
    "PROCESS_EMAIL_VISIBILITY_SECONDS", 120, cast=int
)
PROCESS_EMAIL_WAIT_SECONDS = config("PROCESS_EMAIL_WAIT_SECONDS", 5, cast=int)
PROCESS_EMAIL_HEALTHCHECK_MAX_AGE = config(
    "PROCESS_EMAIL_HEALTHCHECK_MAX_AGE", 120, cast=int
)

# Django 3.2 switches default to BigAutoField
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Patching for django-types
django_stubs_ext.monkeypatch()
