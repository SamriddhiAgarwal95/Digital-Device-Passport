# core_passport/admin.py

from django.contrib import admin
from .models import DigitalPassport, EventLog

# Register your models to be visible in the admin interface
admin.site.register(DigitalPassport)
admin.site.register(EventLog)