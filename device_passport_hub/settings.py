"""
Django settings for device_passport_hub project.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-z28d9^98azv9ov8@tmc(6ycuy!yexmv$=42n&!*27hs(c0*u&x'
DEBUG = True

# FINAL FIX: Allows connection from the Kali VM (192.168.1.7)
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '10.63.80.74','10.80.40.226'] 


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # PROJECT APPS
    'core_passport', 
    
    # THIRD-PARTY APPS
    'rest_framework', 
    'corsheaders', # For allowing cross-origin requests from Kali
]

MIDDLEWARE = [
    # CORS Middleware must be first
    'corsheaders.middleware.CorsMiddleware', 
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # FINAL FIX: CSRF Middleware is commented out for external development stability
    # 'django.middleware.csrf.CsrfViewMiddleware', 
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'device_passport_hub.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'], # <-- TEMPLATE DIRECTORY ADDED
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

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ... (Password validation settings remain unchanged)

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# CORS Configuration for Kali VM
CORS_ALLOWED_ORIGINS = [
    "http://192.168.1.7:8000",
    "http://192.168.1.7",
]
CORS_ALLOW_ALL_HEADERS = True
CORS_ALLOW_METHODS = [
    'POST',
    'OPTIONS',
]

# REST FRAMEWORK Configuration to enforce JSON
REST_FRAMEWORK = {
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
}