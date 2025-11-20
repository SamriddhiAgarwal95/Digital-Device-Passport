"""
Django settings for device_passport_hub project.
... (rest of the comments remain unchanged)
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-z28d9^98azv9ov8@tmc(6ycuy!yexmv$=42n&!*27hs(c0*u&x'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # ---------------------------------------------
    # 💥 REQUIRED ADDITIONS START HERE 💥
    # ---------------------------------------------
    
    # 1. Your Custom App: This contains your models, views, and core logic.
    'core_passport', 
    
    # 2. Third-Party App: Django REST Framework (DRF) is necessary 
    #    to easily build the secure API endpoint that the Kali VM will POST data to.
    'rest_framework', 
    
    'corsheaders',
    # ---------------------------------------------
    # 💥 REQUIRED ADDITIONS END HERE 💥
    # ---------------------------------------------
]

MIDDLEWARE = [
# ... (rest of the middleware list remains unchanged)
    'corsheaders.middleware.CorsMiddleware', # <--- ADD THIS LINE (must be first)
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'device_passport_hub.urls'

TEMPLATES = [
# ... (rest of TEMPLATES remains unchanged)
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'device_passport_hub.wsgi.application'


# Database
# ... (DATABASES remains unchanged)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# ... (AUTH_PASSWORD_VALIDATORS remains unchanged)

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# ... (LANGUAGE_CODE, TIME_ZONE, USE_I18N, USE_TZ remains unchanged)

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# ... (STATIC_URL remains unchanged)

STATIC_URL = 'static/'

# Default primary key field type
# ... (DEFAULT_AUTO_FIELD remains unchanged)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS Configuration for Kali VM
CORS_ALLOWED_ORIGINS = [
    "http://192.168.1.7:8000",
    "http://192.168.1.7",
]
# For testing, we allow all headers and methods
CORS_ALLOW_ALL_HEADERS = True
CORS_ALLOW_METHODS = [
    'POST',
    'OPTIONS',
]
# We must disable CSRF checking for API requests, especially from other origins
CSRF_TRUSTED_ORIGINS = [
    "http://192.168.1.7:8000",
    "http://192.168.1.7",
]
CSRF_EXEMPT_VIEWS = ['core_passport.views.MintPassportAPIView']