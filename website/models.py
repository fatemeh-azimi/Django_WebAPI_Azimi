from django.db import models
from accounts.models import Profile, User


# Create your models here.
class Contact(models.Model):
    email = models.ForeignKey('accounts.User', on_delete=models.CASCADE)      
    # email = models.EmailField()
    name = models.ForeignKey('accounts.Profile', on_delete=models.CASCADE)      
    # name = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    message = models.TextField()
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_date']

    def __str__(self):
        return self.name


class Newsletter(models.Model):
    email = models.EmailField()
    def __str__(self):
        return self.email