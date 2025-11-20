# core_passport/models.py

from django.db import models
from hashlib import sha256
import json 
from django.utils import timezone 

class DigitalPassport(models.Model):
    # 1. PRIMARY KEY: The unique identifier for the device
    imei_serial = models.CharField(max_length=50, unique=True, verbose_name="IMEI / Serial Number")
    
    # 2. WIPE CERTIFICATION FIELDS (The Proof)
    mint_date = models.DateTimeField(auto_now_add=True)
    wipe_standard = models.CharField(max_length=100) 
    is_certified = models.BooleanField(default=False) 
    
    # 3. DLT/IMMUTABILITY FIELD (The Novelty)
    chain_hash = models.CharField(max_length=64, blank=True)
    
    # Method to generate the hash before saving (DLT Simulation)
    def save(self, *args, **kwargs):
        if not self.chain_hash:
            data_to_hash = {
                'imei': self.imei_serial,
                'date': timezone.now().isoformat(),
                'certified': self.is_certified,
                'standard': self.wipe_standard
            }
            json_string = json.dumps(data_to_hash, sort_keys=True)
            self.chain_hash = sha256(json_string.encode('utf-8')).hexdigest()
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Passport for {self.imei_serial}"


class EventLog(models.Model):
    # Link this event to a specific passport
    passport = models.ForeignKey(DigitalPassport, on_delete=models.CASCADE, related_name='events')
    
    event_type = models.CharField(max_length=50) 
    event_data = models.JSONField() 
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.event_type} on {self.passport.imei_serial}"