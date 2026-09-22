from django.conf import settings
from django.db import models


class Invoice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    user_id = models.IntegerField()
    number = models.CharField(max_length=32)
    total = models.IntegerField()
