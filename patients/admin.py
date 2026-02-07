"""
Django Admin Configuration for Patient Management.

Provides administrative interface for managing patients and lookup tables.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import (
    AcquisitionChannel,
    Patient,
    PatientFolderCounter,
    PatientImportExportJob,
    PatientMergeHistory,
    PatientReferral,
    PatientType,
)


# ====================
# Inline Admin Classes
# ====================

class PatientReferralInline(admin.StackedInline):
    """Inline for managing referral data on Patient admin page."""
    model = PatientReferral
    extra = 0
    max_num = 1
    can_delete = True
    fk_name = "patient"
    raw_id_fields = ("referrer_patient",)
    readonly_fields = ("id", "created_at", "updated_at")
    fieldsets = (
        (None, {
            "fields": ("referrer_patient", "referrer_name"),
            "description": "Either select an existing patient as referrer OR enter an external referrer name."
        }),
        (_("Metadata"), {
            "fields": ("id", "created_at", "updated_at"),
            "classes": ("collapse",),
        }),
    )


# ====================
# Main Admin Classes
# ====================

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    """Admin configuration for Patient model."""
    
    list_display = (
        "folder_number",
        "full_name",
        "phone_number",
        "age_display",
        "gender",
        "patient_type",
        "is_child",
        "created_at",
    )
    list_filter = (
        "gender",
        "is_child",
        "patient_type",
        "acquisition_channel",
        "nationality",
        "created_at",
    )
    search_fields = (
        "folder_number",
        "first_name",
        "last_name",
        "phone_number",
        "email",
        "guardian_name",
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    readonly_fields = (
        "id",
        "folder_number",
        "age_display",
        "created_at",
        "updated_at",
    )
    raw_id_fields = ("patient_type", "acquisition_channel")
    inlines = [PatientReferralInline]

    fieldsets = (
        (_("Identity"), {
            "fields": (
                "id",
                "folder_number",
                "profile_picture_url",
            ),
        }),
        (_("Personal Information"), {
            "fields": (
                ("first_name", "last_name"),
                ("date_of_birth", "age_display"),
                "gender",
                "phone_number",
                "email",
            ),
        }),
        (_("Additional Details"), {
            "fields": (
                "occupation",
                "address",
                "nationality",
                "patient_type",
            ),
            "classes": ("collapse",),
        }),
        (_("Child Patient"), {
            "fields": (
                "is_child",
                "guardian_name",
                "guardian_phone",
                "guardian_occupation",
                "guardian_address",
                "guardian_email",
            ),
            "classes": ("collapse",),
            "description": "Guardian information is required if patient is a child.",
        }),
        (_("Acquisition"), {
            "fields": ("acquisition_channel",),
            "classes": ("collapse",),
        }),
        (_("Timestamps"), {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",),
        }),
    )

    @admin.display(description=_("Full Name"))
    def full_name(self, obj):
        return obj.full_name

    @admin.display(description=_("Age"))
    def age_display(self, obj):
        age = obj.age
        if age is None:
            return "-"
        return f"{age} years"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "patient_type",
            "acquisition_channel",
        )


@admin.register(PatientType)
class PatientTypeAdmin(admin.ModelAdmin):
    """Admin configuration for PatientType lookup table."""
    
    list_display = ("name", "description", "is_active", "patient_count", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "description")
    ordering = ("name",)
    readonly_fields = ("id", "created_at", "updated_at")

    fieldsets = (
        (None, {
            "fields": ("id", "name", "description", "is_active"),
        }),
        (_("Timestamps"), {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",),
        }),
    )

    @admin.display(description=_("Patients"))
    def patient_count(self, obj):
        count = obj.patients.count()
        return count


@admin.register(AcquisitionChannel)
class AcquisitionChannelAdmin(admin.ModelAdmin):
    """Admin configuration for AcquisitionChannel lookup table."""
    
    list_display = ("code", "name", "is_active", "patient_count", "created_at")
    list_filter = ("is_active",)
    search_fields = ("code", "name", "description")
    ordering = ("name",)
    readonly_fields = ("id", "created_at", "updated_at")
    prepopulated_fields = {"code": ("name",)}

    fieldsets = (
        (None, {
            "fields": ("id", "code", "name", "description", "is_active"),
        }),
        (_("Timestamps"), {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",),
        }),
    )

    @admin.display(description=_("Patients"))
    def patient_count(self, obj):
        count = obj.patients.count()
        return count


@admin.register(PatientReferral)
class PatientReferralAdmin(admin.ModelAdmin):
    """Admin configuration for PatientReferral model."""
    
    list_display = (
        "patient",
        "referrer_display",
        "created_at",
    )
    search_fields = (
        "patient__folder_number",
        "patient__first_name",
        "patient__last_name",
        "referrer_patient__folder_number",
        "referrer_name",
    )
    ordering = ("-created_at",)
    readonly_fields = ("id", "created_at", "updated_at")
    raw_id_fields = ("patient", "referrer_patient")

    fieldsets = (
        (None, {
            "fields": (
                "id",
                "patient",
                "referrer_patient",
                "referrer_name",
            ),
        }),
        (_("Timestamps"), {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",),
        }),
    )

    @admin.display(description=_("Referrer"))
    def referrer_display(self, obj):
        if obj.referrer_patient:
            return format_html(
                '<a href="/admin/patients/patient/{}/change/">{}</a>',
                obj.referrer_patient.id,
                obj.referrer_patient.full_name,
            )
        return obj.referrer_name or "-"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "patient",
            "referrer_patient",
        )


@admin.register(PatientFolderCounter)
class PatientFolderCounterAdmin(admin.ModelAdmin):
    """Admin configuration for PatientFolderCounter (read-only)."""
    
    list_display = ("year", "last_sequence")
    ordering = ("-year",)
    readonly_fields = ("year", "last_sequence")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(PatientMergeHistory)
class PatientMergeHistoryAdmin(admin.ModelAdmin):
    """Admin configuration for PatientMergeHistory (read-only audit log)."""
    
    list_display = (
        "created_at",
        "primary_patient_display",
        "secondary_folder_number",
        "merged_by_display",
        "merge_reason_short",
    )
    list_filter = ("created_at", "merged_by")
    search_fields = (
        "primary_patient__folder_number",
        "primary_patient__first_name",
        "primary_patient__last_name",
        "secondary_folder_number",
        "merge_reason",
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    readonly_fields = (
        "id",
        "primary_patient",
        "secondary_patient_id",
        "secondary_folder_number",
        "secondary_patient_snapshot",
        "merged_by",
        "merge_reason",
        "fields_updated",
        "related_records_transferred",
        "created_at",
        "updated_at",
    )
    raw_id_fields = ("primary_patient", "merged_by")

    fieldsets = (
        (_("Merge Details"), {
            "fields": (
                "id",
                "primary_patient",
                "secondary_folder_number",
                "secondary_patient_id",
                "merge_reason",
            ),
        }),
        (_("Changes Made"), {
            "fields": ("fields_updated", "related_records_transferred"),
        }),
        (_("Secondary Patient Snapshot"), {
            "fields": ("secondary_patient_snapshot",),
            "classes": ("collapse",),
        }),
        (_("Audit"), {
            "fields": ("merged_by", "created_at", "updated_at"),
        }),
    )

    @admin.display(description=_("Primary Patient"))
    def primary_patient_display(self, obj):
        if obj.primary_patient:
            return format_html(
                '<a href="/admin/patients/patient/{}/change/">{}</a>',
                obj.primary_patient.id,
                obj.primary_patient.folder_number,
            )
        return "-"

    @admin.display(description=_("Merged By"))
    def merged_by_display(self, obj):
        return obj.merged_by.email if obj.merged_by else "-"

    @admin.display(description=_("Reason"))
    def merge_reason_short(self, obj):
        if obj.merge_reason:
            return obj.merge_reason[:50] + "..." if len(obj.merge_reason) > 50 else obj.merge_reason
        return "-"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            "primary_patient",
            "merged_by",
        )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(PatientImportExportJob)
class PatientImportExportJobAdmin(admin.ModelAdmin):
    """Admin for managing import/export jobs."""
    
    list_display = (
        "id",
        "job_type",
        "status_display",
        "file_format",
        "source_filename",
        "progress_display",
        "initiated_by_display",
        "created_at",
        "completed_at",
    )
    list_filter = (
        "job_type",
        "status",
        "file_format",
        "created_at",
    )
    search_fields = (
        "id",
        "source_filename",
        "initiated_by__email",
    )
    readonly_fields = (
        "id",
        "job_type",
        "status",
        "file_format",
        "initiated_by",
        "source_file",
        "source_filename",
        "result_file",
        "total_rows",
        "processed_rows",
        "success_count",
        "error_count",
        "skip_count",
        "started_at",
        "completed_at",
        "error_message",
        "row_errors",
        "options",
        "export_filters",
        "celery_task_id",
        "created_at",
        "updated_at",
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"
    
    fieldsets = (
        (_("Job Information"), {
            "fields": ("id", "job_type", "status", "file_format"),
        }),
        (_("Files"), {
            "fields": ("source_filename", "source_file", "result_file"),
        }),
        (_("Progress"), {
            "fields": ("total_rows", "processed_rows", "success_count", "error_count", "skip_count"),
        }),
        (_("Timing"), {
            "fields": ("started_at", "completed_at"),
        }),
        (_("Errors"), {
            "fields": ("error_message", "row_errors"),
            "classes": ("collapse",),
        }),
        (_("Configuration"), {
            "fields": ("options", "export_filters"),
            "classes": ("collapse",),
        }),
        (_("System"), {
            "fields": ("initiated_by", "celery_task_id", "created_at", "updated_at"),
        }),
    )

    @admin.display(description=_("Status"))
    def status_display(self, obj):
        colors = {
            "PENDING": "orange",
            "PROCESSING": "blue",
            "COMPLETED": "green",
            "FAILED": "red",
            "CANCELLED": "gray",
        }
        color = colors.get(obj.status, "black")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.status,
        )

    @admin.display(description=_("Progress"))
    def progress_display(self, obj):
        if obj.total_rows == 0:
            return "-"
        percentage = obj.progress_percentage
        return format_html(
            '{}/{} ({:.1f}%)',
            obj.processed_rows,
            obj.total_rows,
            percentage,
        )

    @admin.display(description=_("Initiated By"))
    def initiated_by_display(self, obj):
        return obj.initiated_by.email if obj.initiated_by else "-"

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("initiated_by")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

