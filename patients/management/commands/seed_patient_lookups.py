from __future__ import annotations

import logging

from django.core.management.base import BaseCommand
from django.db import transaction

from patients.models import AcquisitionChannel, PatientType

logger = logging.getLogger(__name__)


# ---------------------------
# Seed data (safe defaults)
# ---------------------------
DEFAULT_ACQUISITION_CHANNELS = [
    # (code, name, description)
    (AcquisitionChannel.CODE_WALK_IN, "Walk-in", "Patient came without a referral or prior booking."),
    (AcquisitionChannel.CODE_REFERRED, "Referred", "Patient was referred by someone (existing patient or external referrer)."),
    # Optional common channels:
    ("SOCIAL_MEDIA", "Social Media", "Patient discovered the clinic through social media."),
    ("GOOGLE_SEARCH", "Google Search", "Patient found the clinic via search."),
]

DEFAULT_PATIENT_TYPES = [
    # (code, name, description)
    (PatientType.CODE_GENERAL, "General", "Default patient category."),
    # Optional examples:
    ("ORTHO", "Ortho", "Orthodontics patient category."),
]


def _normalize_code(code: str) -> str:
    return (code or "").strip().upper()


def _get_by_code_case_insensitive(model, desired_code: str):
    """
    Returns an existing instance if found case-insensitively, else None.
    Example: existing 'walk_in' but desired is 'WALK_IN'.
    """
    return model.objects.filter(code__iexact=desired_code).first()


class Command(BaseCommand):
    help = "Seeds default PatientType and AcquisitionChannel records (safe + idempotent)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--defaults-only",
            action="store_true",
            help="Seed only the required defaults (WALK_IN, REFERRED, GENERAL).",
        )
        parser.add_argument(
            "--deactivate-missing",
            action="store_true",
            help=(
                "Deactivate ONLY known seeded records that are not present in the chosen seed list. "
                "Does not touch clinic-created custom records."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be written without changing the database.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        defaults_only = bool(options["defaults_only"])
        deactivate_missing = bool(options["deactivate_missing"])
        dry_run = bool(options["dry_run"])

        # Required defaults always included
        required_acq = {
            AcquisitionChannel.CODE_WALK_IN,
            AcquisitionChannel.CODE_REFERRED,
        }
        required_types = {
            PatientType.CODE_GENERAL,
        }

        if defaults_only:
            acquisition_seed = [row for row in DEFAULT_ACQUISITION_CHANNELS if _normalize_code(row[0]) in required_acq]
            patient_type_seed = [row for row in DEFAULT_PATIENT_TYPES if _normalize_code(row[0]) in required_types]
        else:
            acquisition_seed = DEFAULT_ACQUISITION_CHANNELS
            patient_type_seed = DEFAULT_PATIENT_TYPES

        # All known seeded codes (used to safely deactivate only “system defaults”)
        all_seeded_acq_codes = {_normalize_code(c) for c, *_ in DEFAULT_ACQUISITION_CHANNELS}
        all_seeded_type_codes = {_normalize_code(c) for c, *_ in DEFAULT_PATIENT_TYPES}

        self.stdout.write(self.style.MIGRATE_HEADING("Seeding Patient Lookup Tables..."))

        # --------------------------
        # AcquisitionChannel seeding
        # --------------------------
        self.stdout.write(self.style.MIGRATE_HEADING("AcquisitionChannel"))

        desired_acq_codes = set()
        for code, name, description in acquisition_seed:
            code = _normalize_code(code)
            desired_acq_codes.add(code)

            existing = _get_by_code_case_insensitive(AcquisitionChannel, code)

            if dry_run:
                action = "UPDATE" if existing else "CREATE"
                self.stdout.write(f" - {action} {code}: name='{name}', is_active=True")
                continue

            if existing:
                # Update in-place, reactivate if needed
                existing.code = code
                existing.name = name.strip()
                existing.description = description or ""
                existing.is_active = True
                existing.save(update_fields=["code", "name", "description", "is_active", "updated_at"])
            else:
                AcquisitionChannel.objects.create(
                    code=code,
                    name=name.strip(),
                    description=description or "",
                    is_active=True,
                )

        if deactivate_missing and not dry_run:
            # SAFE: only deactivate known seeded codes that were NOT chosen for this run
            to_deactivate = list(all_seeded_acq_codes - desired_acq_codes)
            if to_deactivate:
                AcquisitionChannel.objects.filter(code__in=to_deactivate).update(is_active=False)

        # --------------------
        # PatientType seeding
        # --------------------
        self.stdout.write(self.style.MIGRATE_HEADING("PatientType"))

        desired_type_codes = set()
        for code, name, description in patient_type_seed:
            code = _normalize_code(code)
            desired_type_codes.add(code)

            existing = _get_by_code_case_insensitive(PatientType, code)

            if dry_run:
                action = "UPDATE" if existing else "CREATE"
                self.stdout.write(f" - {action} {code}: name='{name}', is_active=True")
                continue

            if existing:
                existing.code = code
                existing.name = name.strip()
                existing.description = description or ""
                existing.is_active = True
                existing.save(update_fields=["code", "name", "description", "is_active", "updated_at"])
            else:
                PatientType.objects.create(
                    code=code,
                    name=name.strip(),
                    description=description or "",
                    is_active=True,
                )

        if deactivate_missing and not dry_run:
            # SAFE: only deactivate known seeded codes that were NOT chosen for this run
            to_deactivate = list(all_seeded_type_codes - desired_type_codes)
            if to_deactivate:
                PatientType.objects.filter(code__in=to_deactivate).update(is_active=False)

        self.stdout.write(self.style.SUCCESS("Done. Lookup tables seeded successfully."))


# Examples:
# - Seed only required defaults:
#   python manage.py seed_patient_lookups --defaults-only
#
# - Seed defaults + common extras:
#   python manage.py seed_patient_lookups
#
# - Dry run:
#   python manage.py seed_patient_lookups --dry-run
#
# - Maintenance mode (safe deactivation of only known seeded defaults):
#   python manage.py seed_patient_lookups --defaults-only --deactivate-missing
