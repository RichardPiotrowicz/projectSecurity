from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Messages(models.Model):
    sender = models.CharField(max_length=100)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=1000)
    