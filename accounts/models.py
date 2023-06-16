from django.db import models
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser, PermissionsMixin)
from django.db.models.fields.related import ForeignKey
from django.utils.translation import ugettext_lazy as _
from django.db.models.signals import post_save
from django.dispatch import receiver


# Create your models here.
class UserManager(BaseUserManager):
    """
    Custom User Model manager where email is the unique 
    identifiers for authentication instead of usernames.
    """
    def create_user(self, email, password, **extra_fields):
        """
        create and save a user with the given email and password and extra_fields.
        """
        if not email:
            raise ValueError(-('the email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, email, password, **extra_fields):
        """
        create and save a superuser with the given email and password.
        """
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError(-('superuser must have is_staff=True'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(-('superuser must have is_superuser=True'))
        return self.create_user(email, password, **extra_fields)

    def create_staffuser(self, email, password, **extra_fields):
        """
        create and save a staffuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError(-('staffuser must have is_staff=True'))
        if extra_fields.get('is_verified') is not True:
            raise ValueError(-('staffuser must have is_verified=True'))
        return self.create_user(email, password, **extra_fields)



AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model for our app
    """
    email = models.EmailField(max_length=255, unique=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    
    auth_provider = models.CharField(max_length=255, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
 
    REQUIRED_FIELDS = [] #ejbary kardan por shodan yek sery az fild ha
    USERNAME_FIELD = 'email'
    
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    objects = UserManager()

    def __str__(self) -> str:
        return self.email
    
    @property
    def fullname(self):
        return f"{self.first_name} {self.last_name}"



class Profile(models.Model):
    """
    Profile class for each user which is being created to hold the information
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    image = models.ImageField(null=True, blank=True)
    discription = models.TextField()
    
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    def __str__(self) -> str:
        return self.user.email

@receiver(post_save, sender=User)
def save_profile(sender, instance, created, **kwargs):
    """
    Signal for post creating a user which activates when a user being created ONLY
    """
    if created:
        Profile.objects.create(user=instance)


