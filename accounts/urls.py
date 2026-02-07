from django.urls import path

from . import views

urlpatterns = [
    # --- Auth (Cookie JWT) ---
    path("csrf/", views.CSRFCookieView.as_view(), name="csrf-cookie"),
    path("login/", views.CustomTokenObtainPairView.as_view(), name="auth-login"),
    path("refresh/", views.CustomTokenRefreshView.as_view(), name="auth-refresh"),
    path("logout/", views.logout_view, name="auth-logout"),
    path("me/", views.CurrentUserView.as_view(), name="auth-me"),

    # --- Password reset / management ---
    path("password-reset/request/", views.CustomPasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password-reset/validate/", views.CustomPasswordResetValidateView.as_view(), name="password-reset-validate"),
    path("password-reset/confirm/", views.CustomPasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("password/change/", views.PasswordChangeView.as_view(), name="password-change"),

    # --- User management (Admin) ---
    path("users/", views.UserListView.as_view(), name="users-list"),
    path("users/register/", views.UserRegistrationView.as_view(), name="users-register"),
    path("users/<uuid:pk>/", views.UserDetailRetrieveUpdateDestroyView.as_view(), name="users-detail"),
    path("users/<uuid:pk>/permissions/", views.UserPermissionsView.as_view(), name="users-permissions"),
    path("permissions/", views.PermissionListView.as_view(), name="permissions-list"),
]
