# These group names MUST exist in Django Admin (auth.Group)

from .models import UserRole

# Map your user_role codes to Django Group names
ROLE_GROUP_MAP = {
    UserRole.ADMIN: "Admin",
    UserRole.SECRETARY: "Secretary",
    UserRole.DENTIST: "Dentist",
}
