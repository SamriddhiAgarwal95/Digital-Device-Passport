# core_passport/views.py
# ------------------------------------------------------------------
# CRITICAL: ENSURE THESE IMPORTS ARE AT THE TOP OF views.py
# ------------------------------------------------------------------
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import PassportMintSerializer
from .models import DigitalPassport 
from django.views.decorators.csrf import csrf_exempt # <-- ADD THIS IMPORT
from django.utils.decorators import method_decorator # <-- ADD THIS IMPORT
@method_decorator(csrf_exempt, name='dispatch') # <-- ADD THIS DECORATOR
class MintPassportAPIView(APIView):
    # ... (rest of the class code)


    """
    API endpoint for the wiping device (Kali VM) to submit CoE data and mint a 
    new Digital Passport (DLT entry).
    """
    def post(self, request):
        serializer = PassportMintSerializer(data=request.data)
        
        if serializer.is_valid():
            # Check for duplicate IMEI before saving (prevents double-minting)
            if DigitalPassport.objects.filter(imei_serial=serializer.validated_data['imei_serial']).exists():
                 return Response({
                    "error": "Passport already exists.",
                    "detail": "A Digital Passport for this device has already been minted."
                }, status=status.HTTP_409_CONFLICT)
            
            try:
                # Creates the database entry and auto-calculates the chain_hash
                passport = serializer.create(serializer.validated_data)
                
                return Response({
                    "message": "Digital Passport Minted Successfully.",
                    "imei": passport.imei_serial,
                    "passport_hash": passport.chain_hash 
                }, status=status.HTTP_201_CREATED)
            
            except Exception as e:
                return Response({
                    "error": "Failed to mint passport.",
                    "detail": str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

        # Returns validation errors if the data is bad (e.g., wipe failed)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)