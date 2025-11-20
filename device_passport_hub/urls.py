# device_passport_hub/urls.py

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # This line connects your API app under the /api/v1/ prefix
    path('api/v1/', include('core_passport.urls')), 
]