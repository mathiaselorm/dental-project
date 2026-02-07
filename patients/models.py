from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Gender(models.TextChoices):
    MALE = "Male", "Male"
    FEMALE = "Female", "Female"


# Ghana +233 E.164 format (e.g. +233241234567)
ghana_phone_validator = RegexValidator(
    regex=r"^\+233\d{9}$",
    message="Phone number must be in Ghana format: +233XXXXXXXXX (9 digits after +233).",
)


def normalize_ghana_phone(phone: str | None) -> str | None:
    """
    Normalize phone number to Ghana E.164 format (+233XXXXXXXXX).
    
    Accepts:
    - +233XXXXXXXXX (already normalized)
    - 0XXXXXXXXX (local format)
    - 233XXXXXXXXX (missing +)
    - XXXXXXXXX (9 digits, assumes Ghana)
    
    Returns None if empty or cannot be normalized.
    """
    if not phone:
        return None
    
    # Remove all non-digit characters except leading +
    cleaned = phone.strip()
    has_plus = cleaned.startswith("+")
    digits = "".join(c for c in cleaned if c.isdigit())
    
    if not digits:
        return None
    
    # Already in correct format
    if has_plus and digits.startswith("233") and len(digits) == 12:
        return f"+{digits}"
    
    # Missing + but has 233 prefix
    if digits.startswith("233") and len(digits) == 12:
        return f"+{digits}"
    
    # Local format: 0XX XXX XXXX (10 digits starting with 0)
    if digits.startswith("0") and len(digits) == 10:
        return f"+233{digits[1:]}"
    
    # Just 9 digits (assumes Ghana)
    if len(digits) == 9:
        return f"+233{digits}"
    
    # Return as-is with + prefix if has digits (let validator catch invalid)
    return f"+{digits}" if digits else None


class PatientType(TimeStampedModel):
    """
    Dynamic patient category shown in the Patient Type dropdown.

    Keep a stable `code` so the system can reliably default to GENERAL even if the
    display name is renamed.
    """
    CODE_GENERAL = "GENERAL"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    code = models.SlugField(
        max_length=50,
        unique=True,
        help_text="Stable system code e.g. GENERAL, VIP, ORTHO. (Seed GENERAL as default)",
    )
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "patient_type"
        ordering = ["name"]
        indexes = [models.Index(fields=["is_active", "name"])]

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.code:
            self.code = self.code.strip().upper()
        if self.name:
            self.name = self.name.strip()

    @classmethod
    def get_default_general(cls):
        return cls.objects.filter(code__iexact=cls.CODE_GENERAL, is_active=True).first()


class AcquisitionChannel(TimeStampedModel):
    """
    Dynamic acquisition channel shown in dropdown.

    Keep a stable 'code' so business rules can reliably detect:
    - WALK_IN default
    - REFERRED flow
    """
    CODE_WALK_IN = "WALK_IN"
    CODE_REFERRED = "REFERRED"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    code = models.SlugField(max_length=50, unique=True)  # e.g. WALK_IN, REFERRED, SOCIAL
    name = models.CharField(max_length=100, unique=True)  # display label (can be renamed)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "acquisition_channel"
        ordering = ["name"]
        indexes = [models.Index(fields=["is_active", "name"])]

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.code:
            self.code = self.code.strip().upper()
        if self.name:
            self.name = self.name.strip()

    @classmethod
    def get_default_walk_in(cls):
        return cls.objects.filter(code__iexact=cls.CODE_WALK_IN, is_active=True).first()

    @classmethod
    def get_default_referred(cls):
        return cls.objects.filter(code__iexact=cls.CODE_REFERRED, is_active=True).first()


class PatientFolderCounter(models.Model):
    """
    Concurrency-safe yearly sequence for folder numbers like DEN-2026-001.
    """
    year = models.PositiveIntegerField(primary_key=True)
    last_sequence = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "patient_folder_counter"


class SoftDeleteManager(models.Manager):
    """
    Default manager: filters out soft-deleted records.
    """
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class Patient(TimeStampedModel):
    """
    Represents a patient record (the Digital Folder cover).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    folder_number = models.CharField(
        max_length=20,
        unique=True,
        editable=False,
        db_index=True,
        help_text="Immutable patient folder number e.g. DEN-2026-001",
    )

    profile_picture_url = models.URLField(
        max_length=255,
        blank=True,
        null=True,
        help_text="URL to the patient's profile avatar (optional).",
    )

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)

    date_of_birth = models.DateField()
    gender = models.CharField(max_length=6, choices=Gender.choices)

    phone_number = models.CharField(
        max_length=15,
        validators=[ghana_phone_validator],
        db_index=True,
    )
    email = models.EmailField(blank=True, null=True)  # NOT unique by default (families may share)

    # Required conceptually; we default them if not provided.
    patient_type = models.ForeignKey(
        PatientType,
        on_delete=models.PROTECT,
        related_name="patients",
        null=False,
        blank=False,
        help_text="Dynamic patient category (defaults to GENERAL if omitted).",
    )

    occupation = models.CharField(max_length=255, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    nationality = models.CharField(max_length=100, blank=True, null=True)

    # Child workflow
    is_child = models.BooleanField(default=False, db_index=True)

    guardian_name = models.CharField(max_length=255, blank=True, null=True)
    guardian_phone = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        validators=[ghana_phone_validator],
    )
    guardian_occupation = models.CharField(max_length=255, blank=True, null=True)
    guardian_address = models.CharField(max_length=255, blank=True, null=True)
    guardian_email = models.EmailField(blank=True, null=True)

    acquisition_channel = models.ForeignKey(
        AcquisitionChannel,
        on_delete=models.PROTECT,
        related_name="patients",
        null=False,
        blank=False,
        help_text="Acquisition channel (defaults to WALK_IN if omitted).",
    )

    # Soft delete fields (for audit/compliance)
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deleted_patients",
        help_text="User who deleted this patient record.",
    )

    # Managers
    objects = SoftDeleteManager()        # Default: excludes deleted
    all_objects = models.Manager()       # Includes deleted records

    class Meta:
        db_table = "patient"
        ordering = ["last_name", "first_name"]
        indexes = [
            models.Index(fields=["last_name", "first_name"]),
            models.Index(fields=["phone_number"]),
            models.Index(fields=["is_child", "last_name"]),
            models.Index(fields=["patient_type"]),
            models.Index(fields=["acquisition_channel"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=Q(is_child=False) | (Q(guardian_name__isnull=False) & Q(guardian_phone__isnull=False)),
                name="guardian_required_if_child",
            ),
            models.CheckConstraint(
                check=Q(is_child=True)
                | (
                    Q(guardian_name__isnull=True)
                    & Q(guardian_phone__isnull=True)
                    & Q(guardian_occupation__isnull=True)
                    & Q(guardian_address__isnull=True)
                    & Q(guardian_email__isnull=True)
                ),
                name="guardian_must_be_null_if_not_child",
            ),
        ]
        # Critical for soft-delete models:
        # allow relations to resolve soft-deleted patients using all_objects.
        base_manager_name = "all_objects"
        default_manager_name = "objects"

    def __str__(self):
        return f"{self.folder_number} - {self.first_name} {self.last_name}"

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def age(self) -> int | None:
        if not self.date_of_birth:
            return None
        today = timezone.localdate()
        years = today.year - self.date_of_birth.year
        if (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day):
            years -= 1
        return max(years, 0)

    def clean(self):
        super().clean()

        if self.email:
            self.email = self.email.strip().lower()

        # Convert empty strings to NULL for guardian fields
        for f in ["guardian_name", "guardian_phone", "guardian_occupation", "guardian_address", "guardian_email"]:
            if getattr(self, f, None) == "":
                setattr(self, f, None)

        # Guardian validation (better messages than DB constraint)
        if self.is_child:
            if not self.guardian_name:
                raise ValidationError({"guardian_name": "Guardian name is required for a child patient."})
            if not self.guardian_phone:
                raise ValidationError({"guardian_phone": "Guardian phone is required for a child patient."})
        else:
            guardian_any = any(
                getattr(self, f) not in (None, "")
                for f in ["guardian_name", "guardian_phone", "guardian_occupation", "guardian_address", "guardian_email"]
            )
            if guardian_any:
                raise ValidationError("Guardian fields must be empty when patient is not marked as a child.")

    def save(self, *args, **kwargs):
        # Skip heavy validation when using update_fields (partial updates)
        update_fields = kwargs.get("update_fields")
        
        # Prevent folder_number changes after creation
        if self.pk:
            old = Patient.all_objects.filter(pk=self.pk).values_list("folder_number", flat=True).first()
            if old and self.folder_number and old != self.folder_number:
                raise ValueError("folder_number is immutable and cannot be changed.")

        # Only apply defaults and normalization for full saves (not partial updates)
        if update_fields is None:
            # Normalize phone numbers
            if self.phone_number:
                self.phone_number = normalize_ghana_phone(self.phone_number) or self.phone_number
            if self.guardian_phone:
                self.guardian_phone = normalize_ghana_phone(self.guardian_phone) or self.guardian_phone
            
            # Normalize email
            if self.email:
                self.email = self.email.strip().lower()
            if self.guardian_email:
                self.guardian_email = self.guardian_email.strip().lower()
            
            # Convert empty strings to NULL for guardian fields
            for f in ["guardian_name", "guardian_phone", "guardian_occupation", "guardian_address", "guardian_email"]:
                if getattr(self, f, None) == "":
                    setattr(self, f, None)

            # Apply defaults (only if omitted)
            if not self.acquisition_channel_id:
                default_walk_in = AcquisitionChannel.get_default_walk_in()
                if not default_walk_in:
                    raise ValidationError({"acquisition_channel": "Default WALK_IN acquisition channel is missing/inactive. Seed it or create one."})
                self.acquisition_channel = default_walk_in

            if not self.patient_type_id:
                default_general = PatientType.get_default_general()
                if not default_general:
                    raise ValidationError({"patient_type": "Default GENERAL patient type is missing/inactive. Seed it or create one."})
                self.patient_type = default_general

            if not self.folder_number:
                self.folder_number = self._generate_folder_number()

        return super().save(*args, **kwargs)

    def soft_delete(self, deleted_by=None):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = deleted_by
        self.save(update_fields=["is_deleted", "deleted_at", "deleted_by", "updated_at"])

    def restore(self):
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=["is_deleted", "deleted_at", "deleted_by", "updated_at"])

    @staticmethod
    def _generate_folder_number() -> str:
        year = timezone.localdate().year
        with transaction.atomic():
            counter, _ = PatientFolderCounter.objects.select_for_update().get_or_create(year=year)
            counter.last_sequence += 1
            counter.save(update_fields=["last_sequence"])
            seq = str(counter.last_sequence).zfill(3)
            return f"DEN-{year}-{seq}"


class PatientReferral(TimeStampedModel):
    """
    Stores referral details only when Patient.acquisition_channel is 'REFERRED'.

    Exactly one of:
    - referrer_patient (existing patient)
    - referrer_name (external person name)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    patient = models.OneToOneField(
        Patient,
        on_delete=models.CASCADE,
        related_name="referral",
    )

    referrer_patient = models.ForeignKey(
        Patient,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="referred_patients",
    )
    referrer_name = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "patient_referral"
        constraints = [
            models.CheckConstraint(
                check=(
                    (Q(referrer_patient__isnull=False) & Q(referrer_name__isnull=True))
                    | (Q(referrer_patient__isnull=True) & Q(referrer_name__isnull=False))
                ),
                name="exactly_one_referrer_source",
            )
        ]

    def clean(self):
        super().clean()

        if self.referrer_name == "":
            self.referrer_name = None

        if self.referrer_patient_id and self.patient_id and self.referrer_patient_id == self.patient_id:
            raise ValidationError({"referrer_patient": "A patient cannot refer themselves."})
        
        # Note: Validation that referral only exists for REFERRED channel
        # is enforced by the services layer (single source of truth)


class PatientMergeHistory(TimeStampedModel):
    """
    Audit trail for patient merge operations.
    Tracks which patients were merged and by whom.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    primary_patient = models.ForeignKey(
        Patient,
        on_delete=models.SET_NULL,
        null=True,
        related_name="merge_history_as_primary",
        help_text="The patient record that was kept.",
    )

    secondary_patient_id = models.UUIDField(
        help_text="UUID of the patient that was merged (may be deleted).",
    )
    secondary_folder_number = models.CharField(
        max_length=20,
        help_text="Folder number of the merged patient (for reference).",
    )
    secondary_patient_snapshot = models.JSONField(
        help_text="Snapshot of the secondary patient data at time of merge.",
    )

    merged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="patient_merges_performed",
    )

    merge_reason = models.TextField(blank=True, default="", help_text="Optional reason for the merge.")
    fields_updated = models.JSONField(default=list, help_text="List of fields updated on the primary patient.")
    related_records_transferred = models.JSONField(default=dict, help_text="Summary of related records transferred.")

    class Meta:
        db_table = "patient_merge_history"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["primary_patient", "created_at"]),
            models.Index(fields=["secondary_patient_id"]),
            models.Index(fields=["merged_by", "created_at"]),
        ]

    def __str__(self):
        primary = self.primary_patient.folder_number if self.primary_patient else "N/A"
        return f"Merge: {self.secondary_folder_number} → {primary}"


class PatientImportExportJob(TimeStampedModel):
    """
    Track async import/export job status, progress, and results.
    """

    class JobType(models.TextChoices):
        IMPORT = "IMPORT", "Import"
        EXPORT = "EXPORT", "Export"

    class JobStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PROCESSING = "PROCESSING", "Processing"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    class FileFormat(models.TextChoices):
        CSV = "CSV", "CSV"
        EXCEL = "EXCEL", "Excel (XLSX)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    job_type = models.CharField(max_length=10, choices=JobType.choices, db_index=True)
    status = models.CharField(max_length=20, choices=JobStatus.choices, default=JobStatus.PENDING, db_index=True)
    file_format = models.CharField(max_length=10, choices=FileFormat.choices)

    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="patient_import_export_jobs",
    )

    source_file = models.CharField(max_length=500, blank=True, null=True)
    source_filename = models.CharField(max_length=255, blank=True, null=True)
    result_file = models.CharField(max_length=500, blank=True, null=True)

    total_rows = models.PositiveIntegerField(default=0)
    processed_rows = models.PositiveIntegerField(default=0)
    success_count = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    skip_count = models.PositiveIntegerField(default=0)

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    error_message = models.TextField(blank=True, default="")
    row_errors = models.JSONField(default=list, help_text="[{row: int, errors: {...}}]")

    options = models.JSONField(default=dict, help_text="Job config: skip_duplicates, update_existing, etc.")
    export_filters = models.JSONField(default=dict, help_text="Filters applied during export.")
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        db_table = "patient_import_export_job"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["job_type", "status"]),
            models.Index(fields=["initiated_by", "created_at"]),
            models.Index(fields=["status", "created_at"]),
        ]

    def __str__(self):
        return f"{self.job_type} Job {self.id} - {self.status}"

    @property
    def progress_percentage(self) -> float:
        if self.total_rows == 0:
            return 0.0
        return round((self.processed_rows / self.total_rows) * 100, 2)

    @property
    def duration_seconds(self) -> float | None:
        if not self.started_at:
            return None
        end_time = self.completed_at or timezone.now()
        return (end_time - self.started_at).total_seconds()

    def mark_started(self):
        self.status = self.JobStatus.PROCESSING
        self.started_at = timezone.now()
        self.save(update_fields=["status", "started_at", "updated_at"])

    def mark_completed(self):
        self.status = self.JobStatus.COMPLETED
        self.completed_at = timezone.now()
        self.save(update_fields=["status", "completed_at", "updated_at"])

    def mark_failed(self, error_message: str):
        self.status = self.JobStatus.FAILED
        self.error_message = error_message
        self.completed_at = timezone.now()
        self.save(update_fields=["status", "error_message", "completed_at", "updated_at"])

    def add_row_error(self, row_number: int, errors: dict):
        self.row_errors.append({"row": row_number, "errors": errors})
        self.error_count += 1
        # Caller decides when to save/batch.
