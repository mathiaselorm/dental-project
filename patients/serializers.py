# patients/serializers.py

from __future__ import annotations

import os
from uuid import UUID

from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import (
    AcquisitionChannel,
    Patient,
    PatientReferral,
    PatientType,
)
from .services.patients import (
    PatientValidationError,
    register_patient,
    update_patient,
)

# ----------------------------
# System defaults (reference model constants for consistency)
# ----------------------------
DEFAULT_PATIENT_TYPE_CODE = PatientType.CODE_GENERAL
DEFAULT_ACQUISITION_CHANNEL_CODE = AcquisitionChannel.CODE_WALK_IN


# ----------------------------
# Lookup serializers (read-only)
# ----------------------------

class PatientTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PatientType
        fields = ("id", "name", "description", "is_active")
        read_only_fields = ("id",)


class AcquisitionChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcquisitionChannel
        fields = ("id", "code", "name", "description", "is_active")
        read_only_fields = ("id",)


# ----------------------------
# Referral serializers
# ----------------------------

class PatientReferrerMiniSerializer(serializers.ModelSerializer):
    """
    Minimal referrer representation to avoid recursion.
    """
    full_name = serializers.CharField(read_only=True)

    class Meta:
        model = Patient
        fields = ("id", "folder_number", "full_name")
        read_only_fields = fields


class PatientReferralReadSerializer(serializers.ModelSerializer):
    referrer_patient = PatientReferrerMiniSerializer(read_only=True)

    class Meta:
        model = PatientReferral
        fields = ("id", "referrer_patient", "referrer_name", "created_at", "updated_at")
        read_only_fields = fields


class PatientReferralInputSerializer(serializers.Serializer):
    """
    Input for referral (only when channel is REFERRED).
    Exactly one of:
      - referrer_patient_id
      - referrer_name
    """
    referrer_patient_id = serializers.UUIDField(required=False, allow_null=True)
    referrer_name = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    def validate(self, attrs):
        pid = attrs.get("referrer_patient_id")
        name = attrs.get("referrer_name")

        has_pid = bool(pid)
        has_name = bool(name and str(name).strip())

        if has_pid and has_name:
            raise serializers.ValidationError(
                _("Provide either referrer_patient_id OR referrer_name, not both.")
            )
        if not has_pid and not has_name:
            raise serializers.ValidationError(
                _("Referral requires referrer_patient_id or referrer_name.")
            )

        if has_name:
            attrs["referrer_name"] = str(name).strip()

        return attrs


# ----------------------------
# Patient serializers
# ----------------------------

class PatientReadSerializer(serializers.ModelSerializer):
    """
    Rich output format for patient details.
    """
    age = serializers.IntegerField(read_only=True)
    full_name = serializers.CharField(read_only=True)

    patient_type = PatientTypeSerializer(read_only=True)
    acquisition_channel = AcquisitionChannelSerializer(read_only=True)

    referral = PatientReferralReadSerializer(read_only=True)

    class Meta:
        model = Patient
        fields = (
            "id",
            "folder_number",
            "profile_picture_url",
            "first_name",
            "last_name",
            "full_name",
            "date_of_birth",
            "age",
            "gender",
            "phone_number",
            "email",
            "patient_type",
            "occupation",
            "address",
            "nationality",
            "is_child",
            "guardian_name",
            "guardian_phone",
            "guardian_occupation",
            "guardian_address",
            "guardian_email",
            "acquisition_channel",
            # soft-delete metadata (read-only)
            "is_deleted",
            "deleted_at",
            "deleted_by_id",
            "created_at",
            "updated_at",
            "referral",
        )
        read_only_fields = fields


class PatientListSerializer(serializers.ModelSerializer):
    """
    Lightweight list serializer for folder search & browsing.
    """
    age = serializers.IntegerField(read_only=True)
    full_name = serializers.CharField(read_only=True)
    patient_type_name = serializers.CharField(source="patient_type.name", read_only=True)

    class Meta:
        model = Patient
        fields = (
            "id",
            "folder_number",
            "full_name",
            "phone_number",
            "age",
            "gender",
            "patient_type_name",
            "is_deleted",
            "created_at",
        )
        read_only_fields = fields


class PatientWriteSerializer(serializers.ModelSerializer):
    """
    Input serializer used for create/update.

    Accepts lookups in a clean explicit way:
      - patient_type_id OR patient_type_name OR patient_type_code
      - acquisition_channel_id OR acquisition_channel_code

    Defaults (create only, if omitted):
      - patient_type -> GENERAL (via code)
      - acquisition_channel -> WALK_IN

    Referral is nested as `referral` only when acquisition channel is REFERRED.
    """

    # Lookups (write-only)
    patient_type_id = serializers.UUIDField(required=False, allow_null=True, write_only=True)
    patient_type_name = serializers.CharField(required=False, allow_null=True, allow_blank=True, write_only=True)
    patient_type_code = serializers.CharField(required=False, allow_null=True, allow_blank=True, write_only=True)

    acquisition_channel_id = serializers.UUIDField(required=False, allow_null=True, write_only=True)
    acquisition_channel_code = serializers.CharField(required=False, allow_null=True, allow_blank=True, write_only=True)

    referral = PatientReferralInputSerializer(required=False, allow_null=True, write_only=True)

    class Meta:
        model = Patient
        fields = (
            # core fields
            "profile_picture_url",
            "first_name",
            "last_name",
            "date_of_birth",
            "gender",
            "phone_number",
            "email",
            "occupation",
            "address",
            "nationality",
            "is_child",
            # guardian fields
            "guardian_name",
            "guardian_phone",
            "guardian_occupation",
            "guardian_address",
            "guardian_email",
            # lookups
            "patient_type_id",
            "patient_type_name",
            "patient_type_code",
            "acquisition_channel_id",
            "acquisition_channel_code",
            # referral (optional)
            "referral",
        )

    # ----------------------------
    # Field-level normalization
    # ----------------------------

    def validate_email(self, value):
        if value is None:
            return value
        v = value.strip().lower()
        return v or None

    def validate_guardian_email(self, value):
        if value is None:
            return value
        v = value.strip().lower()
        return v or None

    def validate_date_of_birth(self, value):
        if value and value > timezone.localdate():
            raise serializers.ValidationError(_("Date of birth cannot be in the future."))
        return value

    # ----------------------------
    # Cross-field validation
    # ----------------------------

    def validate(self, attrs):
        # Mutually exclusive patient type inputs (only one allowed)
        pt_inputs = sum(bool(attrs.get(k)) for k in ["patient_type_id", "patient_type_name", "patient_type_code"])
        if pt_inputs > 1:
            raise serializers.ValidationError(
                {"patient_type": _("Provide only one of: patient_type_id, patient_type_name, or patient_type_code.")}
            )

        # Mutually exclusive acquisition channel inputs
        if attrs.get("acquisition_channel_id") and attrs.get("acquisition_channel_code"):
            raise serializers.ValidationError(
                {"acquisition_channel": _("Provide either acquisition_channel_id or acquisition_channel_code, not both.")}
            )

        # Apply defaults ONLY on create (do not override existing on update)
        # Services layer handles actual resolution; we just ensure a code is passed
        if self.instance is None:
            if not attrs.get("patient_type_id") and not (attrs.get("patient_type_name") or "").strip() and not (attrs.get("patient_type_code") or "").strip():
                attrs["patient_type_code"] = DEFAULT_PATIENT_TYPE_CODE

            if not attrs.get("acquisition_channel_id") and not (attrs.get("acquisition_channel_code") or "").strip():
                attrs["acquisition_channel_code"] = DEFAULT_ACQUISITION_CHANNEL_CODE

        # Child vs adult rules (serializer-level for clean errors)
        is_child = attrs.get("is_child")
        if is_child is True:
            if not attrs.get("guardian_name"):
                raise serializers.ValidationError({"guardian_name": _("Guardian name is required for a child patient.")})
            if not attrs.get("guardian_phone"):
                raise serializers.ValidationError({"guardian_phone": _("Guardian phone is required for a child patient.")})
        elif is_child is False:
            # If explicitly set false, clear guardian fields for strict DB constraints
            for f in ("guardian_name", "guardian_phone", "guardian_occupation", "guardian_address", "guardian_email"):
                attrs[f] = None

        # NOTE: Referral validation is handled in services layer (single source of truth)
        # Services will validate referral requirements based on acquisition channel
        # This avoids duplicate validation logic

        return attrs

    # ----------------------------
    # Persistence via services
    # ----------------------------

    def create(self, validated_data):
        request = self.context.get("request")
        try:
            return register_patient(payload=validated_data, request=request)
        except PatientValidationError as e:
            raise serializers.ValidationError(e.errors)

    def update(self, instance, validated_data):
        request = self.context.get("request")
        try:
            return update_patient(patient=instance, payload=validated_data, request=request)
        except PatientValidationError as e:
            raise serializers.ValidationError(e.errors)


# ----------------------------
# Duplicate Detection Serializers
# ----------------------------

class DuplicateCheckInputSerializer(serializers.Serializer):
    """
    Input for checking potential duplicates before patient creation.
    """
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    threshold = serializers.IntegerField(required=False, default=30, min_value=10, max_value=100)

    def validate(self, attrs):
        has_data = any([
            (attrs.get("first_name") or "").strip(),
            (attrs.get("last_name") or "").strip(),
            (attrs.get("phone_number") or "").strip(),
            attrs.get("date_of_birth"),
            (attrs.get("email") or "").strip(),
        ])
        if not has_data:
            raise serializers.ValidationError(
                _("At least one field (first_name, last_name, phone_number, date_of_birth, or email) is required.")
            )
        return attrs


class DuplicateMatchSerializer(serializers.Serializer):
    """
    Output serializer for a potential duplicate match.
    """
    patient = PatientListSerializer(read_only=True)
    score = serializers.IntegerField(read_only=True)
    match_reasons = serializers.ListField(child=serializers.CharField(), read_only=True)


class DuplicateGroupSerializer(serializers.Serializer):
    """
    Output serializer for a group of duplicate patients.
    """
    patients = PatientListSerializer(many=True, read_only=True)
    count = serializers.IntegerField(read_only=True)


# ----------------------------
# Patient Merge Serializers
# ----------------------------

class PatientMergeInputSerializer(serializers.Serializer):
    """
    Input for merging two patients.
    """
    primary_patient_id = serializers.UUIDField(required=True)
    secondary_patient_id = serializers.UUIDField(required=True)
    merge_fields = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
    )
    merge_reason = serializers.CharField(required=False, allow_blank=True, default="")

    def validate(self, attrs):
        if attrs["primary_patient_id"] == attrs["secondary_patient_id"]:
            raise serializers.ValidationError(
                {"secondary_patient_id": _("Cannot merge a patient with itself.")}
            )
        return attrs


class PatientMergeHistorySerializer(serializers.Serializer):
    """
    Output serializer for merge history records.
    """
    id = serializers.UUIDField(read_only=True)
    primary_patient = PatientListSerializer(read_only=True)
    secondary_patient_id = serializers.UUIDField(read_only=True)
    secondary_folder_number = serializers.CharField(read_only=True)
    secondary_patient_snapshot = serializers.JSONField(read_only=True)
    merged_by_email = serializers.SerializerMethodField()
    merge_reason = serializers.CharField(read_only=True)
    fields_updated = serializers.ListField(read_only=True)
    related_records_transferred = serializers.JSONField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    def get_merged_by_email(self, obj):
        return obj.merged_by.email if getattr(obj, "merged_by", None) else None


class PatientMergeResultSerializer(serializers.Serializer):
    """
    Output serializer for merge operation result.
    """
    primary_patient = PatientReadSerializer(read_only=True)
    merge_history = PatientMergeHistorySerializer(read_only=True)
    message = serializers.CharField(read_only=True)


# ----------------------------
# Import/Export Serializers
# ----------------------------

class PatientImportOptionsSerializer(serializers.Serializer):
    skip_duplicates = serializers.BooleanField(required=False, default=False)
    update_existing = serializers.BooleanField(required=False, default=False)
    duplicate_threshold = serializers.IntegerField(required=False, default=50, min_value=10, max_value=100)
    skip_invalid_rows = serializers.BooleanField(required=False, default=True)
    dry_run = serializers.BooleanField(required=False, default=False)


class PatientImportUploadSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    options = PatientImportOptionsSerializer(required=False)

    def validate_file(self, value):
        max_size = 10 * 1024 * 1024  # 10MB
        if value.size > max_size:
            raise serializers.ValidationError(
                _("File too large. Maximum size is %(size)sMB.") % {"size": max_size // (1024 * 1024)}
            )

        filename = value.name or ""
        ext = os.path.splitext(filename.lower())[1]
        allowed = {".csv", ".xlsx", ".xls", ".xlsm"}
        if ext not in allowed:
            raise serializers.ValidationError(
                _("Unsupported file format '%(ext)s'. Allowed formats: %(allowed)s") % {
                    "ext": ext,
                    "allowed": ", ".join(sorted(allowed)),
                }
            )

        return value


class PatientExportOptionsSerializer(serializers.Serializer):
    file_format = serializers.ChoiceField(choices=["CSV", "EXCEL"], default="EXCEL")
    include_deleted = serializers.BooleanField(required=False, default=False)
    date_from = serializers.DateField(required=False, allow_null=True)
    date_to = serializers.DateField(required=False, allow_null=True)
    patient_type_ids = serializers.ListField(child=serializers.UUIDField(), required=False, default=list)
    acquisition_channel_ids = serializers.ListField(child=serializers.UUIDField(), required=False, default=list)
    search_query = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate(self, attrs):
        date_from = attrs.get("date_from")
        date_to = attrs.get("date_to")
        if date_from and date_to and date_from > date_to:
            raise serializers.ValidationError({"date_to": _("End date must be after start date.")})
        return attrs


class ImportExportJobSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    job_type = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    file_format = serializers.CharField(read_only=True)

    initiated_by_email = serializers.SerializerMethodField()

    source_filename = serializers.CharField(read_only=True)
    result_file_url = serializers.SerializerMethodField()

    total_rows = serializers.IntegerField(read_only=True)
    processed_rows = serializers.IntegerField(read_only=True)
    success_count = serializers.IntegerField(read_only=True)
    error_count = serializers.IntegerField(read_only=True)
    skip_count = serializers.IntegerField(read_only=True)
    progress_percentage = serializers.FloatField(read_only=True)

    created_at = serializers.DateTimeField(read_only=True)
    started_at = serializers.DateTimeField(read_only=True)
    completed_at = serializers.DateTimeField(read_only=True)
    duration_seconds = serializers.FloatField(read_only=True)

    error_message = serializers.CharField(read_only=True)
    row_errors = serializers.ListField(read_only=True)

    options = serializers.JSONField(read_only=True)
    export_filters = serializers.JSONField(read_only=True)

    def get_initiated_by_email(self, obj):
        return obj.initiated_by.email if getattr(obj, "initiated_by", None) else None

    def get_result_file_url(self, obj):
        # Return stored path; view layer can convert to absolute URL if needed.
        return obj.result_file or None


class ImportExportJobListSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    job_type = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    file_format = serializers.CharField(read_only=True)
    source_filename = serializers.CharField(read_only=True)
    total_rows = serializers.IntegerField(read_only=True)
    success_count = serializers.IntegerField(read_only=True)
    error_count = serializers.IntegerField(read_only=True)
    progress_percentage = serializers.FloatField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    completed_at = serializers.DateTimeField(read_only=True)


class ImportResultRowSerializer(serializers.Serializer):
    row_number = serializers.IntegerField(read_only=True)
    success = serializers.BooleanField(read_only=True)
    action = serializers.CharField(read_only=True)
    patient_id = serializers.UUIDField(read_only=True, allow_null=True)
    folder_number = serializers.CharField(read_only=True, allow_null=True)
    errors = serializers.DictField(read_only=True)
    warnings = serializers.ListField(child=serializers.CharField(), read_only=True)


class ImportResultSerializer(serializers.Serializer):
    total_rows = serializers.IntegerField(read_only=True)
    processed_rows = serializers.IntegerField(read_only=True)
    created_count = serializers.IntegerField(read_only=True)
    updated_count = serializers.IntegerField(read_only=True)
    skipped_count = serializers.IntegerField(read_only=True)
    error_count = serializers.IntegerField(read_only=True)
    row_results = ImportResultRowSerializer(many=True, read_only=True)
    errors = serializers.ListField(read_only=True)
    warnings = serializers.ListField(child=serializers.CharField(), read_only=True)
