from django.db import models

class Sender(models.Model):
    sender_name = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
# Create your models here.
