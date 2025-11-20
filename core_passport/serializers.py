# core_passport/serializers.py

from rest_framework import serializers
from .models import DigitalPassport 

class PassportMintSerializer(serializers.Serializer):
    """
    Serializer for the Certificate of Erasure (CoE) data received from the wiping device.
    """
    imei_serial = serializers.CharField(max_length=50)
    wipe_status = serializers.CharField(max_length=50) 
    wipe_standard = serializers.CharField(max_length=100)
    verification_log = serializers.CharField(required=False, allow_blank=True) 

    def validate_wipe_status(self, value):
        """Custom validation to ensure the wipe was successful."""
        if value != "SUCCESS":
            raise serializers.ValidationError("Wipe process reported failure. Cannot mint passport.")
        return value

    def create(self, validated_data):
        """This method Mints the Passport (creates the database record)."""
        if validated_data['wipe_status'] != 'SUCCESS':
             raise serializers.ValidationError("Cannot mint passport on failure.")
             
        passport = DigitalPassport.objects.create(
            imei_serial=validated_data['imei_serial'],
            is_certified=True,
            wipe_standard=validated_data['wipe_standard']
        )
        return passport