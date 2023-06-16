from rest_framework import permissions
from rest_framework.pagination import PageNumberPagination
from accounts.models import Profile, User


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has an `owner` attribute.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Instance must have an attribute named `owner`.
        return obj.author.user == request.user





class DjangoModelPermissions(permissions.BasePermission):
    """
    The request is authenticated using `django.contrib.auth` permissions.
    See: https://docs.djangoproject.com/en/dev/topics/auth/#permissions

    It ensures that the user is authenticated, and has the appropriate
    `add`/`change`/`delete` permissions on the model.

    This permission can only be applied against view classes that
    provide a `.queryset` attribute.
    """

    # Map methods into required permission codes.
    # Override this if you need to also provide 'view' permissions,
    # or if you want to provide custom permission codes.
    perms_map = {
        'GET': [User.objects.all()],
        'OPTIONS': [User.objects.all()],
        'HEAD': [User.objects.all()],
        'POST': [User.objects.filter(is_staff=True)],
        'PUT': [User.objects.filter(is_staff=True)],
        'PATCH': [User.objects.filter(is_staff=True)],
        'DELETE': [User.objects.filter(is_staff=True)], #['is_staff'],
    }
