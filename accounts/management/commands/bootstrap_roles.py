from __future__ import annotations

import logging

from django.conf import settings
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

from accounts.roles import ROLE_GROUP_MAP

logger = logging.getLogger(__name__)

ROLE_GROUP_NAMES = list(ROLE_GROUP_MAP.values())


def _resolve_permissions(specs: list[str]) -> set[Permission]:
    """
    Convert a list of permission specs into Permission objects.

    Supported formats:
      - "*"                    -> all permissions
      - "app_label.*"          -> all permissions for that app_label
      - "app_label.codename"   -> one permission
    Missing permissions are ignored (logged).
    """
    perms: set[Permission] = set()

    if not specs:
        return perms

    if "*" in specs:
        return set(Permission.objects.all())

    for spec in specs:
        spec = (spec or "").strip()
        if not spec:
            continue

        if spec.endswith(".*"):
            app_label = spec.split(".", 1)[0]
            cts = ContentType.objects.filter(app_label=app_label)
            perms.update(Permission.objects.filter(content_type__in=cts))
            continue

        if "." not in spec:
            logger.warning("Invalid permission spec '%s' (expected app_label.codename). Skipping.", spec)
            continue

        app_label, codename = spec.split(".", 1)
        ct_qs = ContentType.objects.filter(app_label=app_label)
        perm = Permission.objects.filter(content_type__in=ct_qs, codename=codename).first()
        if perm:
            perms.add(perm)
        else:
            logger.warning("Permission not found for spec '%s'. Skipping.", spec)

    return perms


class Command(BaseCommand):
    help = "Create role groups (Admin, Secretary, Dentist) and optionally assign default permissions."

    def add_arguments(self, parser):
        parser.add_argument(
            "--assign-perms",
            action="store_true",
            help="Assign default permissions to groups from settings.ROLE_DEFAULT_PERMISSIONS (and Admin defaults).",
        )
        parser.add_argument(
            "--reset",
            action="store_true",
            help="If set, clears existing permissions on those groups before assigning.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would happen without writing to DB.",
        )

    def handle(self, *args, **options):
        assign_perms = options["assign_perms"]
        reset = options["reset"]
        dry_run = options["dry_run"]

        self.stdout.write(self.style.MIGRATE_HEADING("Bootstrapping role groups..."))

        created = 0
        for name in ROLE_GROUP_NAMES:
            if dry_run:
                exists = Group.objects.filter(name=name).exists()
                self.stdout.write(f" - {'EXISTS' if exists else 'CREATE'} Group: {name}")
                continue

            group, was_created = Group.objects.get_or_create(name=name)
            created += int(was_created)

        self.stdout.write(self.style.SUCCESS(f"Groups ensured. Created={created}, Total={len(ROLE_GROUP_NAMES)}"))

        if not assign_perms:
            self.stdout.write(self.style.WARNING("Permission assignment skipped (use --assign-perms)."))
            return

        # Settings-driven permissions for non-admin groups
        role_defaults = getattr(settings, "ROLE_DEFAULT_PERMISSIONS", {}) or {}

        # If Admin group not specified, default Admin => all permissions
        if "Admin" not in role_defaults:
            role_defaults = dict(role_defaults)
            role_defaults["Admin"] = ["*"]

        self.stdout.write(self.style.MIGRATE_HEADING("Assigning permissions..."))

        for group_name, perm_specs in role_defaults.items():
            if group_name not in ROLE_GROUP_NAMES:
                # ignore unknown keys safely
                continue

            if dry_run:
                self.stdout.write(f" - Would assign perms to {group_name}: {perm_specs}")
                continue

            group = Group.objects.get(name=group_name)

            if reset:
                group.permissions.clear()

            perms = _resolve_permissions(list(perm_specs or []))
            if perms:
                group.permissions.add(*perms)

            self.stdout.write(self.style.SUCCESS(
                f" - {group_name}: assigned {len(perms)} permission(s){' (reset)' if reset else ''}"
            ))

        self.stdout.write(self.style.SUCCESS("Done."))




# python manage.py bootstrap_roles
# python manage.py bootstrap_roles --assign-perms
# python manage.py bootstrap_roles --assign-perms --reset
