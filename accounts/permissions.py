from rest_framework import permissions
from django.contrib.auth import get_user_model
from .models import UserRole

User = get_user_model()


class IsAdmin(permissions.BasePermission):
    """
    Custom permission to allow only Admins to access specific views.
    """
    def has_permission(self, request, view):
        user = request.user
        # Check if the user is authenticated and has the Admin role
        return user.is_authenticated and user.is_superuser or user.user_role == UserRole.ADMIN

class IsDentist(permissions.BasePermission):
    """
    Custom permission to allow only Dentist to access specific views.
    """
    def has_permission(self, request, view):
        user = request.user
        # Check if the user is authenticated and has the Dentist role
        return user.is_authenticated and user.user_role == UserRole.DENTIST
