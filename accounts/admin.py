from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Profile

# Register your models here.
class CustomUserAdmin(UserAdmin):
    """
    Custom admin panel for user management with add and change forms plus password
    """
    model = User
    list_display = ('email', 'is_superuser', 'is_staff', 'is_active', 'is_verified')
    list_filter = ('email', 'is_superuser', 'is_staff', 'is_active', 'is_verified')
    searching_fields = ('email', )
    ordering = ('email', )
    fieldsets = (
        ('Authentication', {
            "fields": (
                    'email', 'password'
            ), 
        }), 
        ('permissions', {
            "fields": (
                    'is_superuser', 'is_staff', 'is_active', 'is_verified'
            ), 
        }), 
        ('group permissions', {
            "fields": (
                    'groups', 'user_permissions'
            ), 
        }), 
        ('important date', {
            "fields": (
                    'last_login', 
            ), 
        }), 
    )
    add_fieldsets = (
         (None, {
            "classes": ('wide', ), 
            "fields": (
                     'email', 'password1', 'password2', 'is_superuser', 'is_staff', 'is_active', 'is_verified'
            ), 
        }), 
    )


class ProfileAdmin(admin.ModelAdmin):
    """
    Custom admin panel for profile management with add and change forms plus password
    """
    model = Profile
    list_display = ['user', 'first_name', 'last_name', 'discription']
    date_hierarchy = 'created_date'
    empty_value_display = '_empty_'
    list_filter = ('user', 'first_name', 'last_name', 'discription')
    search_field = [('user', 'first_name', 'last_name', 'discription')]
    ordering = ('user', )
    


admin.site.register(Profile, ProfileAdmin)
admin.site.register(User, CustomUserAdmin)


