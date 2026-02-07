from __future__ import annotations

import logging
import os
from typing import Any

from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, status
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    OpenApiTypes,
    extend_schema,
    extend_schema_view,
)

from accounts.permissions import IsAdmin, IsFrontDeskStaff

from .models import (
    AcquisitionChannel,
    Patient,
    PatientImportExportJob,
    PatientMergeHistory,
    PatientType,
)
from .serializers import (
    AcquisitionChannelSerializer,
    DuplicateCheckInputSerializer,
    DuplicateMatchSerializer,
    ImportExportJobListSerializer,
    ImportExportJobSerializer,
    PatientExportOptionsSerializer,
    PatientImportUploadSerializer,
    PatientListSerializer,
    PatientMergeHistorySerializer,
    PatientMergeInputSerializer,
    PatientReadSerializer,
    PatientTypeSerializer,
    PatientWriteSerializer,
)

logger = logging.getLogger(__name__)


# =========================
# Small helpers
# =========================

def _log_patient_action(level: str, action: str, user_email: str, folder_number: str, patient_id: str = None):
    """
    Secure logging helper that logs only non-PII identifiers.
    Never logs patient names, phone numbers, or other sensitive data.
    """
    msg = f"{action} by {user_email}: folder={folder_number}"
    if patient_id:
        msg += f", id={patient_id}"
    getattr(logger, level)(msg)


def _is_truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "y", "on")


def _safe_int(value: Any, *, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        i = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None:
        i = max(i, min_value)
    if max_value is not None:
        i = min(i, max_value)
    return i


def _is_admin_request(request, view) -> bool:
    """
    Use your project permission (IsAdmin) consistently instead of is_staff.
    """
    try:
        return IsAdmin().has_permission(request, view)
    except Exception:
        return False


def _can_access_job(request, view, job: PatientImportExportJob) -> bool:
    """
    Admin can access any job. Non-admin can only access own jobs.
    """
    if _is_admin_request(request, view):
        return True
    return bool(request.user.is_authenticated and job.initiated_by_id == getattr(request.user, "id", None))


# =========================
# Query helpers
# =========================

def patient_queryset_base():
    """
    Centralized queryset with select_related to prevent N+1 queries.
    Uses the default manager (SoftDeleteManager) which excludes deleted patients.
    Assumes:
      - patient_type FK
      - acquisition_channel FK
      - referral OneToOne related_name="referral"
      - referral.referrer_patient FK
    """
    return (
        Patient.objects.all()
        .select_related(
            "patient_type",
            "acquisition_channel",
            "referral",
            "referral__referrer_patient",
        )
    )


def patient_queryset_all():
    """
    Queryset that includes ALL patients (including soft-deleted).
    Uses all_objects manager.
    """
    return (
        Patient.all_objects.all()
        .select_related(
            "patient_type",
            "acquisition_channel",
            "referral",
            "referral__referrer_patient",
            "deleted_by",
        )
    )


# =========================
# PATIENTS
# =========================

@extend_schema(
    tags=["Patients"],
    summary="List patients (Folder search)",
    description=(
        "Lists patients for the folder system.\n\n"
        "- Search: `?search=` (folder number, names, phone, email, guardian)\n"
        "- Filter: gender, is_child, patient_type, acquisition_channel, nationality\n"
        "- Ordering: created_at, last_name, folder_number (use `-` for desc)"
    ),
    parameters=[
        OpenApiParameter(
            name="search",
            type=OpenApiTypes.STR,
            required=False,
            description="Search by folder_number, first_name, last_name, phone_number, email, guardian_name.",
        ),
        OpenApiParameter(
            name="ordering",
            type=OpenApiTypes.STR,
            required=False,
            description="Ordering fields: created_at, last_name, folder_number. Prefix with '-' for descending.",
        ),
        OpenApiParameter(
            name="gender",
            type=OpenApiTypes.STR,
            required=False,
            description="Filter by gender value (e.g. Male/Female).",
        ),
        OpenApiParameter(
            name="is_child",
            type=OpenApiTypes.BOOL,
            required=False,
            description="Filter child/adult.",
        ),
        OpenApiParameter(
            name="patient_type",
            type=OpenApiTypes.UUID,
            required=False,
            description="Filter by PatientType id.",
        ),
        OpenApiParameter(
            name="acquisition_channel",
            type=OpenApiTypes.UUID,
            required=False,
            description="Filter by AcquisitionChannel id.",
        ),
        OpenApiParameter(
            name="nationality",
            type=OpenApiTypes.STR,
            required=False,
            description="Filter by nationality.",
        ),
    ],
    responses={
        200: OpenApiResponse(response=PatientListSerializer(many=True), description="Patients returned."),
        401: OpenApiResponse(description="Authentication required."),
    },
)
class PatientListCreateView(generics.ListCreateAPIView):
    """
    GET  /patients/       -> list/search
    POST /patients/       -> create (FrontDeskStaff only)
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    search_fields = [
        "folder_number",
        "first_name",
        "last_name",
        "phone_number",
        "email",
        "guardian_name",
    ]
    ordering_fields = ["created_at", "last_name", "folder_number"]
    ordering = ["-created_at"]

    filterset_fields = {
        "gender": ["exact"],
        "is_child": ["exact"],
        "patient_type": ["exact"],
        "acquisition_channel": ["exact"],
        "nationality": ["exact"],
    }

    def get_queryset(self):
        return patient_queryset_base()

    def get_serializer_class(self):
        return PatientWriteSerializer if self.request.method == "POST" else PatientListSerializer

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsFrontDeskStaff()]
        return [IsAuthenticated()]

    @extend_schema(
        tags=["Patients"],
        summary="Create patient (Create Folder)",
        description=(
            "Creates a patient folder.\n\n"
            "**Rules:**\n"
            "- folder_number is auto-generated and immutable\n"
            "- age is computed from date_of_birth (not stored)\n"
            "- acquisition_channel defaults to WALK_IN if omitted\n"
            "- if acquisition_channel is REFERRED, referral payload is required\n"
            "- referral payload is rejected for non-REFERRED channels\n"
            "- if is_child=true, guardian_name and guardian_phone are required"
        ),
        request=PatientWriteSerializer,
        responses={
            201: OpenApiResponse(response=PatientReadSerializer, description="Patient created."),
            400: OpenApiResponse(description="Validation error."),
            401: OpenApiResponse(description="Authentication required."),
            403: OpenApiResponse(description="Permission denied."),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        patient = serializer.save()
        _log_patient_action(
            "info",
            "Patient created",
            getattr(request.user, "email", "unknown"),
            patient.folder_number,
            str(patient.id),
        )

        return Response(
            PatientReadSerializer(patient, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=["Patients"],
    summary="Retrieve patient folder",
    description="Returns full patient folder details including patient type, acquisition channel, and referral if any.",
    responses={
        200: OpenApiResponse(response=PatientReadSerializer, description="Patient retrieved."),
        401: OpenApiResponse(description="Authentication required."),
        404: OpenApiResponse(description="Patient not found."),
    },
)
class PatientRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /patients/{id}/ -> retrieve (all authenticated)
    PATCH  /patients/{id}/ -> update (FrontDeskStaff only)
    PUT    /patients/{id}/ -> update (FrontDeskStaff only)
    DELETE /patients/{id}/ -> delete (Admin only)
    """
    lookup_field = "id"
    lookup_url_kwarg = "id"

    def get_queryset(self):
        return patient_queryset_base()

    def get_serializer_class(self):
        return PatientWriteSerializer if self.request.method in ("PUT", "PATCH") else PatientReadSerializer

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH"):
            return [IsFrontDeskStaff()]
        if self.request.method == "DELETE":
            return [IsAdmin()]
        return [IsAuthenticated()]

    @extend_schema(
        tags=["Patients"],
        summary="Update patient folder",
        description=(
            "Updates patient folder fields.\n\n"
            "**Rules enforced by services/serializers:**\n"
            "- If is_child=false, guardian fields are cleared\n"
            "- If acquisition_channel becomes REFERRED, referral required unless already exists\n"
            "- If acquisition_channel changes away from REFERRED, referral is removed\n"
            "- folder_number remains immutable\n"
            "- acquisition_channel defaults to WALK_IN when omitted on create"
        ),
        request=PatientWriteSerializer,
        responses={
            200: OpenApiResponse(response=PatientReadSerializer, description="Patient updated."),
            400: OpenApiResponse(description="Validation error."),
            401: OpenApiResponse(description="Authentication required."),
            403: OpenApiResponse(description="Permission denied."),
            404: OpenApiResponse(description="Patient not found."),
        },
    )
    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = PatientWriteSerializer(
            instance,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        patient = serializer.save()

        _log_patient_action(
            "info",
            "Patient updated",
            getattr(request.user, "email", "unknown"),
            patient.folder_number,
            str(patient.id),
        )
        return Response(PatientReadSerializer(patient, context={"request": request}).data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = PatientWriteSerializer(
            instance,
            data=request.data,
            partial=False,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        patient = serializer.save()

        _log_patient_action(
            "info",
            "Patient updated (PUT)",
            getattr(request.user, "email", "unknown"),
            patient.folder_number,
            str(patient.id),
        )
        return Response(PatientReadSerializer(patient, context={"request": request}).data, status=status.HTTP_200_OK)

    @extend_schema(
        tags=["Patients"],
        summary="Delete patient folder (Admin only)",
        description=(
            "Soft-deletes a patient record.\n\n"
            "The patient record is marked as deleted but retained for audit/compliance purposes. "
            "Use the restore endpoint to recover a soft-deleted patient."
        ),
        responses={
            204: OpenApiResponse(description="Patient soft-deleted."),
            401: OpenApiResponse(description="Authentication required."),
            403: OpenApiResponse(description="Permission denied."),
            404: OpenApiResponse(description="Patient not found."),
        },
    )
    def delete(self, request, *args, **kwargs):
        from .services.patients import soft_delete_patient

        instance = self.get_object()
        folder_number = instance.folder_number
        patient_id = str(instance.id)

        soft_delete_patient(patient=instance, request=request)
        _log_patient_action(
            "warning",
            "Patient soft-deleted",
            getattr(request.user, "email", "unknown"),
            folder_number,
            patient_id,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


# =========================
# ALL PATIENTS (INCLUDING DELETED) - Admin Only
# =========================

@extend_schema(
    tags=["Patients (Admin)"],
    summary="List all patients including deleted (Admin only)",
    description=(
        "Lists ALL patients including soft-deleted records.\n\n"
        "- Filter by `is_deleted=true` to see only deleted patients\n"
        "- Filter by `is_deleted=false` to see only active patients"
    ),
    parameters=[
        OpenApiParameter(
            name="is_deleted",
            type=OpenApiTypes.BOOL,
            required=False,
            description="Filter by deletion status.",
        ),
        OpenApiParameter(
            name="search",
            type=OpenApiTypes.STR,
            required=False,
            description="Search by folder_number, first_name, last_name, phone_number.",
        ),
        OpenApiParameter(
            name="ordering",
            type=OpenApiTypes.STR,
            required=False,
            description="Ordering fields: created_at, deleted_at, last_name, folder_number. Prefix '-' for desc.",
        ),
    ],
    responses={
        200: OpenApiResponse(response=PatientListSerializer(many=True), description="All patients returned."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin access required."),
    },
)
class AllPatientsListView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = PatientListSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    search_fields = ["folder_number", "first_name", "last_name", "phone_number"]
    ordering_fields = ["created_at", "deleted_at", "last_name", "folder_number"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = patient_queryset_all()
        is_deleted = self.request.query_params.get("is_deleted")
        if is_deleted is not None:
            qs = qs.filter(is_deleted=_is_truthy(is_deleted))
        return qs


@extend_schema(
    tags=["Patients (Admin)"],
    summary="Restore a deleted patient (Admin only)",
    description="Restores a soft-deleted patient record.",
    responses={
        200: OpenApiResponse(response=PatientReadSerializer, description="Patient restored."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin access required."),
        404: OpenApiResponse(description="Patient not found."),
        400: OpenApiResponse(description="Patient is not deleted."),
    },
)
class PatientRestoreView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, id):
        from .services.patients import restore_patient

        patient = Patient.all_objects.filter(id=id).first()
        if not patient:
            return Response({"detail": _("Patient not found.")}, status=status.HTTP_404_NOT_FOUND)

        if not patient.is_deleted:
            return Response({"detail": _("Patient is not deleted.")}, status=status.HTTP_400_BAD_REQUEST)

        restore_patient(patient=patient, request=request)

        # Reload to ensure current state + relations
        refreshed = patient_queryset_base().filter(id=id).first() or patient

        _log_patient_action(
            "info",
            "Patient restored",
            getattr(request.user, "email", "unknown"),
            refreshed.folder_number,
            str(refreshed.id),
        )

        return Response(PatientReadSerializer(refreshed, context={"request": request}).data, status=status.HTTP_200_OK)


# =========================
# DUPLICATE DETECTION
# =========================

@extend_schema(
    tags=["Duplicate Detection"],
    summary="Check for potential duplicates",
    description=(
        "Check for potential duplicate patients before creating a new record.\n\n"
        "Results with score >= threshold are returned."
    ),
    request=DuplicateCheckInputSerializer,
    responses={
        200: OpenApiResponse(response=DuplicateMatchSerializer(many=True), description="Potential duplicates found."),
        400: OpenApiResponse(description="Validation error."),
        401: OpenApiResponse(description="Authentication required."),
    },
)
class DuplicateCheckView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from .services.patients import find_potential_duplicates

        serializer = DuplicateCheckInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        matches = find_potential_duplicates(
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            phone_number=data.get("phone_number"),
            date_of_birth=data.get("date_of_birth"),
            email=data.get("email"),
            threshold=data.get("threshold", 30),
        )

        return Response(DuplicateMatchSerializer(matches, many=True).data, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Duplicate Detection"],
    summary="Find duplicates for a patient",
    parameters=[
        OpenApiParameter(
            name="threshold",
            type=OpenApiTypes.INT,
            required=False,
            description="Minimum score threshold (default 30).",
        ),
    ],
    responses={
        200: OpenApiResponse(response=DuplicateMatchSerializer(many=True), description="Potential duplicates found."),
        401: OpenApiResponse(description="Authentication required."),
        404: OpenApiResponse(description="Patient not found."),
    },
)
class PatientDuplicatesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        from .services.patients import find_duplicates_for_patient

        patient = Patient.objects.filter(id=id).first()
        if not patient:
            return Response({"detail": _("Patient not found.")}, status=status.HTTP_404_NOT_FOUND)

        threshold = _safe_int(request.query_params.get("threshold"), default=30, min_value=10, max_value=100)
        matches = find_duplicates_for_patient(patient, threshold=threshold)

        return Response(DuplicateMatchSerializer(matches, many=True).data, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Duplicate Detection"],
    summary="Scan for all duplicate groups (Admin only)",
    description=(
        "Scan the entire patient database for potential duplicate groups.\n\n"
        "⚠️ Resource-intensive. Use sparingly."
    ),
    parameters=[
        OpenApiParameter(
            name="threshold",
            type=OpenApiTypes.INT,
            required=False,
            description="Minimum score threshold (default 40 for batch).",
        ),
    ],
    responses={
        200: OpenApiResponse(description="Duplicate groups found."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin access required."),
    },
)
class DuplicateScanView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        from .services.patients import scan_all_duplicates

        threshold = _safe_int(request.query_params.get("threshold"), default=40, min_value=10, max_value=100)
        duplicate_groups = scan_all_duplicates(threshold=threshold)

        result = []
        for group in duplicate_groups:
            result.append(
                {
                    "patients": PatientListSerializer(group, many=True, context={"request": request}).data,
                    "count": len(group),
                }
            )

        return Response({"total_groups": len(result), "groups": result}, status=status.HTTP_200_OK)


# =========================
# PATIENT MERGE
# =========================

@extend_schema(
    tags=["Patient Merge"],
    summary="Merge two patients (Admin only)",
    request=PatientMergeInputSerializer,
    responses={
        200: OpenApiResponse(description="Patients merged successfully."),
        400: OpenApiResponse(description="Validation error or merge failed."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin access required."),
        404: OpenApiResponse(description="Patient not found."),
    },
)
class PatientMergeView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        from .services.patients import PatientMergeError, merge_patients

        serializer = PatientMergeInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        primary = Patient.all_objects.filter(id=data["primary_patient_id"]).first()
        if not primary:
            return Response({"detail": _("Primary patient not found.")}, status=status.HTTP_404_NOT_FOUND)

        secondary = Patient.all_objects.filter(id=data["secondary_patient_id"]).first()
        if not secondary:
            return Response({"detail": _("Secondary patient not found.")}, status=status.HTTP_404_NOT_FOUND)

        try:
            merged_patient = merge_patients(
                primary_patient=primary,
                secondary_patient=secondary,
                merge_fields=data.get("merge_fields"),
                merge_reason=data.get("merge_reason", ""),
                request=request,
            )
        except PatientMergeError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        _log_patient_action(
            "info",
            f"Patient merge completed (secondary {data['secondary_patient_id']})",
            getattr(request.user, "email", "unknown"),
            merged_patient.folder_number,
            str(merged_patient.id),
        )

        merged_patient = patient_queryset_base().filter(id=merged_patient.id).first() or merged_patient

        return Response(
            {
                "message": _("Patients merged successfully."),
                "primary_patient": PatientReadSerializer(merged_patient, context={"request": request}).data,
                "secondary_folder_number": secondary.folder_number,
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(
    tags=["Patient Merge"],
    summary="Get merge history for a patient",
    responses={
        200: OpenApiResponse(response=PatientMergeHistorySerializer(many=True), description="Merge history returned."),
        401: OpenApiResponse(description="Authentication required."),
        404: OpenApiResponse(description="Patient not found."),
    },
)
class PatientMergeHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        from .services.patients import get_merge_history

        patient = Patient.all_objects.filter(id=id).first()
        if not patient:
            return Response({"detail": _("Patient not found.")}, status=status.HTTP_404_NOT_FOUND)

        history = get_merge_history(patient)
        return Response(PatientMergeHistorySerializer(history, many=True, context={"request": request}).data)


@extend_schema(
    tags=["Patient Merge"],
    summary="List all merge history (Admin only)",
    parameters=[
        OpenApiParameter(
            name="merged_by",
            type=OpenApiTypes.UUID,
            required=False,
            description="Filter by user who performed the merge.",
        ),
    ],
    responses={
        200: OpenApiResponse(response=PatientMergeHistorySerializer(many=True), description="Merge history returned."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin access required."),
    },
)
class AllMergeHistoryView(generics.ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = PatientMergeHistorySerializer

    def get_queryset(self):
        qs = PatientMergeHistory.objects.all().select_related("primary_patient", "merged_by").order_by("-created_at")
        merged_by = self.request.query_params.get("merged_by")
        if merged_by:
            qs = qs.filter(merged_by_id=merged_by)
        return qs


# =========================
# PATIENT TYPES (CRUD)
# =========================

@extend_schema_view(
    get=extend_schema(
        tags=["Patient Types"],
        summary="List patient types",
        parameters=[
            OpenApiParameter(
                name="is_active",
                type=OpenApiTypes.BOOL,
                required=False,
                description="Filter by active status.",
            )
        ],
        responses={
            200: OpenApiResponse(response=PatientTypeSerializer(many=True), description="Patient types returned."),
            401: OpenApiResponse(description="Authentication required."),
        },
    ),
    post=extend_schema(
        tags=["Patient Types"],
        summary="Create patient type",
        responses={
            201: OpenApiResponse(response=PatientTypeSerializer, description="Patient type created."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
        },
    ),
)
class PatientTypeListCreateView(generics.ListCreateAPIView):
    serializer_class = PatientTypeSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    ordering_fields = ["name", "created_at"]
    ordering = ["name"]
    search_fields = ["name"]

    def get_queryset(self):
        qs = PatientType.objects.all().order_by("name")
        is_active = self.request.query_params.get("is_active")
        if is_active is not None:
            qs = qs.filter(is_active=_is_truthy(is_active))
        return qs

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAdmin()]
        return [IsAuthenticated()]


@extend_schema_view(
    get=extend_schema(
        tags=["Patient Types"],
        summary="Retrieve patient type",
        responses={
            200: OpenApiResponse(response=PatientTypeSerializer, description="Patient type details."),
            404: OpenApiResponse(description="Patient type not found."),
        },
    ),
    put=extend_schema(
        tags=["Patient Types"],
        summary="Update patient type",
        responses={
            200: OpenApiResponse(response=PatientTypeSerializer, description="Patient type updated."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Patient type not found."),
        },
    ),
    patch=extend_schema(
        tags=["Patient Types"],
        summary="Partial update patient type",
        responses={
            200: OpenApiResponse(response=PatientTypeSerializer, description="Patient type updated."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Patient type not found."),
        },
    ),
    delete=extend_schema(
        tags=["Patient Types"],
        summary="Delete patient type",
        responses={
            204: OpenApiResponse(description="Patient type deleted."),
            400: OpenApiResponse(description="Patient type is in use."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Patient type not found."),
        },
    ),
)
class PatientTypeRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PatientTypeSerializer
    queryset = PatientType.objects.all()
    lookup_field = "id"
    lookup_url_kwarg = "id"

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH", "DELETE"):
            return [IsAdmin()]
        return [IsAuthenticated()]

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if Patient.objects.filter(patient_type=instance).exists():
            return Response(
                {"detail": _("This patient type is in use. Deactivate it instead (set is_active=false).")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


# =========================
# ACQUISITION CHANNELS (CRUD)
# =========================

@extend_schema_view(
    get=extend_schema(
        tags=["Acquisition Channels"],
        summary="List acquisition channels",
        parameters=[
            OpenApiParameter(
                name="is_active",
                type=OpenApiTypes.BOOL,
                required=False,
                description="Filter by active status.",
            )
        ],
        responses={
            200: OpenApiResponse(response=AcquisitionChannelSerializer(many=True), description="Channels returned."),
            401: OpenApiResponse(description="Authentication required."),
        },
    ),
    post=extend_schema(
        tags=["Acquisition Channels"],
        summary="Create acquisition channel",
        responses={
            201: OpenApiResponse(response=AcquisitionChannelSerializer, description="Channel created."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
        },
    ),
)
class AcquisitionChannelListCreateView(generics.ListCreateAPIView):
    serializer_class = AcquisitionChannelSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    ordering_fields = ["name", "code", "created_at"]
    ordering = ["name"]
    search_fields = ["name", "code"]

    def get_queryset(self):
        qs = AcquisitionChannel.objects.all().order_by("name")
        is_active = self.request.query_params.get("is_active")
        if is_active is not None:
            qs = qs.filter(is_active=_is_truthy(is_active))
        return qs

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAdmin()]
        return [IsAuthenticated()]


@extend_schema_view(
    get=extend_schema(
        tags=["Acquisition Channels"],
        summary="Retrieve acquisition channel",
        responses={
            200: OpenApiResponse(response=AcquisitionChannelSerializer, description="Channel details."),
            404: OpenApiResponse(description="Channel not found."),
        },
    ),
    put=extend_schema(
        tags=["Acquisition Channels"],
        summary="Update acquisition channel",
        responses={
            200: OpenApiResponse(response=AcquisitionChannelSerializer, description="Channel updated."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Channel not found."),
        },
    ),
    patch=extend_schema(
        tags=["Acquisition Channels"],
        summary="Partial update acquisition channel",
        responses={
            200: OpenApiResponse(response=AcquisitionChannelSerializer, description="Channel updated."),
            400: OpenApiResponse(description="Validation error."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Channel not found."),
        },
    ),
    delete=extend_schema(
        tags=["Acquisition Channels"],
        summary="Delete acquisition channel",
        responses={
            204: OpenApiResponse(description="Channel deleted."),
            400: OpenApiResponse(description="Channel is in use."),
            403: OpenApiResponse(description="Admin privileges required."),
            404: OpenApiResponse(description="Channel not found."),
        },
    ),
)
class AcquisitionChannelRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = AcquisitionChannelSerializer
    queryset = AcquisitionChannel.objects.all()
    lookup_field = "id"
    lookup_url_kwarg = "id"

    def get_permissions(self):
        if self.request.method in ("PUT", "PATCH", "DELETE"):
            return [IsAdmin()]
        return [IsAuthenticated()]

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if Patient.objects.filter(acquisition_channel=instance).exists():
            return Response(
                {"detail": _("This acquisition channel is in use. Deactivate it instead (set is_active=false).")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


# =========================
# IMPORT / EXPORT
# =========================

@extend_schema(
    tags=["Import/Export"],
    summary="Upload and import patients from CSV/Excel",
    request=PatientImportUploadSerializer,
    responses={
        202: OpenApiResponse(response=ImportExportJobSerializer, description="Import job created and queued."),
        400: OpenApiResponse(description="Invalid file or options."),
        403: OpenApiResponse(description="Admin permission required."),
    },
)
class PatientImportView(APIView):
    permission_classes = [IsAdmin]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        from django.core.files.storage import default_storage

        from .services.import_export import detect_file_format
        from .tasks import process_patient_import

        serializer = PatientImportUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]
        options = serializer.validated_data.get("options") or {}

        if not options:
            options = {
                "skip_duplicates": _is_truthy(request.data.get("skip_duplicates", "false")),
                "update_existing": _is_truthy(request.data.get("update_existing", "false")),
                "skip_invalid_rows": _is_truthy(request.data.get("skip_invalid_rows", "true")),
                "dry_run": _is_truthy(request.data.get("dry_run", "false")),
                "duplicate_threshold": _safe_int(request.data.get("duplicate_threshold"), default=50, min_value=10, max_value=100),
            }

        try:
            file_format = detect_file_format(uploaded_file.name)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        base_name, ext = os.path.splitext(uploaded_file.name or "patients")
        safe_base = slugify(base_name)[:60] or "patients"
        ts = timezone.now().strftime("%Y%m%d_%H%M%S_%f")
        storage_filename = f"patient_import_export/uploads/{safe_base}_{ts}{ext.lower()}"

        # Use streaming to avoid loading entire file into memory
        # Reset file pointer to beginning before saving
        uploaded_file.seek(0)
        file_path = default_storage.save(storage_filename, uploaded_file)

        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.IMPORT,
            file_format=file_format,
            initiated_by=request.user,
            source_file=file_path,
            source_filename=uploaded_file.name,
            options=options,
        )

        task = process_patient_import.delay(
            job_id=str(job.id),
            source_file_path=file_path,
            original_filename=uploaded_file.name,
            options_dict=options,
        )

        job.celery_task_id = task.id
        job.save(update_fields=["celery_task_id", "updated_at"])

        payload = ImportExportJobSerializer(job, context={"request": request}).data
        payload["message"] = _("Import job created and queued for processing.")
        return Response(payload, status=status.HTTP_202_ACCEPTED)


@extend_schema(
    tags=["Import/Export"],
    summary="Export patients to CSV/Excel",
    request=PatientExportOptionsSerializer,
    responses={
        202: OpenApiResponse(response=ImportExportJobSerializer, description="Export job created and queued."),
        400: OpenApiResponse(description="Invalid options."),
        403: OpenApiResponse(description="Admin permission required."),
    },
)
class PatientExportView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        from .tasks import process_patient_export

        serializer = PatientExportOptionsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        file_format = data.get("file_format", "EXCEL")

        options_dict = {
            "include_deleted": data.get("include_deleted", False),
            "date_from": data["date_from"].isoformat() if data.get("date_from") else None,
            "date_to": data["date_to"].isoformat() if data.get("date_to") else None,
            "patient_type_ids": [str(pid) for pid in data.get("patient_type_ids", [])],
            "acquisition_channel_ids": [str(cid) for cid in data.get("acquisition_channel_ids", [])],
            "search_query": data.get("search_query"),
        }

        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.EXPORT,
            file_format=file_format,
            initiated_by=request.user,
            export_filters=options_dict,
        )

        task = process_patient_export.delay(
            job_id=str(job.id),
            file_format=file_format,
            options_dict=options_dict,
        )

        job.celery_task_id = task.id
        job.save(update_fields=["celery_task_id", "updated_at"])

        payload = ImportExportJobSerializer(job, context={"request": request}).data
        payload["message"] = _("Export job created and queued for processing.")
        return Response(payload, status=status.HTTP_202_ACCEPTED)


@extend_schema(
    tags=["Import/Export"],
    summary="List import/export jobs",
    responses={200: OpenApiResponse(response=ImportExportJobListSerializer(many=True), description="Job list returned.")},
)
class ImportExportJobListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ImportExportJobListSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ["created_at", "completed_at", "status", "job_type"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = PatientImportExportJob.objects.all()

        if not _is_admin_request(self.request, self):
            qs = qs.filter(initiated_by=self.request.user)

        job_type = self.request.query_params.get("job_type")
        if job_type:
            qs = qs.filter(job_type=job_type.upper())

        status_filter = self.request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter.upper())

        return qs


@extend_schema(
    tags=["Import/Export"],
    summary="Get import/export job details",
    responses={
        200: OpenApiResponse(response=ImportExportJobSerializer, description="Job details returned."),
        404: OpenApiResponse(description="Job not found."),
        403: OpenApiResponse(description="Permission denied."),
    },
)
class ImportExportJobDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        try:
            job = PatientImportExportJob.objects.get(id=job_id)
        except PatientImportExportJob.DoesNotExist:
            return Response({"detail": _("Job not found.")}, status=status.HTTP_404_NOT_FOUND)

        if not _can_access_job(request, self, job):
            return Response({"detail": _("Permission denied.")}, status=status.HTTP_403_FORBIDDEN)

        return Response(ImportExportJobSerializer(job, context={"request": request}).data)


@extend_schema(
    tags=["Import/Export"],
    summary="Download import/export result file",
    responses={
        200: OpenApiResponse(description="File download."),
        404: OpenApiResponse(description="Job or file not found."),
        403: OpenApiResponse(description="Permission denied."),
    },
)
class ImportExportJobDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        from django.core.files.storage import default_storage
        from django.http import FileResponse

        try:
            job = PatientImportExportJob.objects.get(id=job_id)
        except PatientImportExportJob.DoesNotExist:
            return Response({"detail": _("Job not found.")}, status=status.HTTP_404_NOT_FOUND)

        if not _can_access_job(request, self, job):
            return Response({"detail": _("Permission denied.")}, status=status.HTTP_403_FORBIDDEN)

        if not job.result_file:
            return Response({"detail": _("No result file available for this job.")}, status=status.HTTP_404_NOT_FOUND)

        if not default_storage.exists(job.result_file):
            return Response({"detail": _("Result file not found. It may have been cleaned up.")}, status=status.HTTP_404_NOT_FOUND)

        ext = ".xlsx" if job.file_format == "EXCEL" else ".csv"
        filename = f"patients_export_{job.id}{ext}" if job.job_type == PatientImportExportJob.JobType.EXPORT else f"import_result_{job.id}{ext}"

        file_obj = default_storage.open(job.result_file, "rb")
        response = FileResponse(file_obj, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


@extend_schema(
    tags=["Import/Export"],
    summary="Cancel import/export job",
    responses={
        200: OpenApiResponse(description="Job cancelled."),
        400: OpenApiResponse(description="Job cannot be cancelled."),
        403: OpenApiResponse(description="Permission denied."),
        404: OpenApiResponse(description="Job not found."),
    },
)
class ImportExportJobCancelView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, job_id):
        from celery.result import AsyncResult

        try:
            job = PatientImportExportJob.objects.get(id=job_id)
        except PatientImportExportJob.DoesNotExist:
            return Response({"detail": _("Job not found.")}, status=status.HTTP_404_NOT_FOUND)

        if not _can_access_job(request, self, job):
            return Response({"detail": _("Permission denied.")}, status=status.HTTP_403_FORBIDDEN)

        if job.status not in [
            PatientImportExportJob.JobStatus.PENDING,
            PatientImportExportJob.JobStatus.PROCESSING,
        ]:
            return Response(
                {"detail": _("Cannot cancel job with status '%(status)s'.") % {"status": job.status}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if job.celery_task_id:
            AsyncResult(job.celery_task_id).revoke(terminate=True)

        job.status = PatientImportExportJob.JobStatus.CANCELLED
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "completed_at", "updated_at"])

        return Response({"detail": _("Job cancelled successfully.")}, status=status.HTTP_200_OK)


@extend_schema(
    tags=["Import/Export"],
    summary="Download import template",
    parameters=[
        OpenApiParameter(
            name="format",
            type=OpenApiTypes.STR,
            required=False,
            description="Template format: 'csv' or 'excel' (default: excel).",
        ),
    ],
    responses={
        200: OpenApiResponse(description="Template file download."),
        401: OpenApiResponse(description="Authentication required."),
    },
)
class ImportTemplateDownloadView(APIView):
    """Download a template file for patient imports."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.http import FileResponse
        import io

        from .services.import_export import (
            generate_import_template_csv,
            generate_import_template_excel,
        )

        file_format = request.query_params.get("format", "excel").lower()

        buf = io.BytesIO()

        if file_format == "csv":
            generate_import_template_csv(buf)
            buf.seek(0)
            filename = "patient_import_template.csv"
            content_type = "text/csv"
        else:
            generate_import_template_excel(buf)
            buf.seek(0)
            filename = "patient_import_template.xlsx"
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        response = FileResponse(buf, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


@extend_schema(
    tags=["Import/Export"],
    summary="Quick export patients (synchronous)",
    description=(
        "Synchronously export patients to CSV or Excel. "
        "For large exports, use the async /export/ endpoint instead."
    ),
    parameters=[
        OpenApiParameter(
            name="format",
            type=OpenApiTypes.STR,
            required=False,
            description="Export format: 'csv' or 'excel' (default: excel).",
        ),
        OpenApiParameter(
            name="include_deleted",
            type=OpenApiTypes.BOOL,
            required=False,
            description="Include soft-deleted patients (default: false).",
        ),
        OpenApiParameter(
            name="search",
            type=OpenApiTypes.STR,
            required=False,
            description="Search query to filter patients.",
        ),
    ],
    responses={
        200: OpenApiResponse(description="Export file download."),
        401: OpenApiResponse(description="Authentication required."),
        403: OpenApiResponse(description="Admin permission required."),
    },
)
class PatientQuickExportView(APIView):
    """Synchronous patient export for smaller datasets."""
    permission_classes = [IsAdmin]

    def get(self, request):
        from django.http import FileResponse
        import io

        from .services.import_export import (
            ExportOptions,
            export_patients_to_csv,
            export_patients_to_excel,
        )

        file_format = request.query_params.get("format", "excel").lower()
        include_deleted = _is_truthy(request.query_params.get("include_deleted", "false"))
        search_query = request.query_params.get("search")

        options = ExportOptions(
            include_deleted=include_deleted,
            search_query=search_query,
        )

        buf = io.BytesIO()

        if file_format == "csv":
            count = export_patients_to_csv(buf, options)
            buf.seek(0)
            filename = f"patients_export_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
            content_type = "text/csv"
        else:
            count = export_patients_to_excel(buf, options)
            buf.seek(0)
            filename = f"patients_export_{timezone.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        response = FileResponse(buf, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
