from __future__ import annotations

from rest_framework import permissions

from .models import UserRole


class BaseRolePermission(permissions.BasePermission):
    """
    Base permission for role checks.

    - Always denies anonymous users.
    - Superusers always pass.
    - Concrete subclasses set `allowed_roles`.
    """

    allowed_roles: tuple[str, ...] = ()

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        return bool(user.user_role in self.allowed_roles)


class IsAdmin(BaseRolePermission):
    """
    Allows access to business Admin users (and superusers).
    """
    allowed_roles = (UserRole.ADMIN,)


class IsDentist(BaseRolePermission):
    """
    Allows access to Dentist users (and superusers).
    """
    allowed_roles = (UserRole.DENTIST,)


class IsSecretary(BaseRolePermission):
    """
    Allows access to Secretary users (and superusers).
    """
    allowed_roles = (UserRole.SECRETARY,)


class IsClinicalStaff(BaseRolePermission):
    """
    Dentist + Admin (and superusers). Useful for clinical modules.
    """
    allowed_roles = (UserRole.DENTIST, UserRole.ADMIN)


class IsFrontDeskStaff(BaseRolePermission):
    """
    Secretary + Admin (and superusers). Useful for patient registration & billing.
    """
    allowed_roles = (UserRole.SECRETARY, UserRole.ADMIN)
