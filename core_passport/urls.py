# core_passport/urls.py

from django.urls import path
from .views import MintPassportAPIView # You need to import the view you created

urlpatterns = [
    # The Kali VM will hit this path: /api/v1/mint/
    path('mint/', MintPassportAPIView.as_view(), name='mint-passport'),
]