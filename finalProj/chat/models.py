from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Messages(models.Model):
    #sender = models.ManyToManyField(User)
    receiver = models.ManyToManyField(User)
    message = models.CharField(max_length=1000)
