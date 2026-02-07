# patients/services/patients.py

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from accounts.audit import audit_log

from ..models import AcquisitionChannel, Patient, PatientReferral, PatientType

logger = logging.getLogger(__name__)


def _log_patient_action(level: str, action: str, folder_number: str, patient_id: str = None):
    """
    Secure logging helper that logs only non-PII identifiers.
    Never logs patient names, phone numbers, or other sensitive data.
    """
    msg = f"{action}: folder={folder_number}"
    if patient_id:
        msg += f", id={patient_id}"
    getattr(logger, level)(msg)


# =========================
# Audit Action Constants
# =========================

class PatientAuditAction:
    """Audit action constants for patient operations."""
    PATIENT_CREATED = "PATIENT_CREATED"
    PATIENT_UPDATED = "PATIENT_UPDATED"
    PATIENT_DELETED = "PATIENT_DELETED"
    PATIENT_RESTORED = "PATIENT_RESTORED"
    PATIENT_VIEWED = "PATIENT_VIEWED"
    PATIENT_MERGED = "PATIENT_MERGED"


# =========================
# Service Exceptions
# =========================

class PatientServiceError(Exception):
    """Base error for patient service operations."""


class PatientValidationError(PatientServiceError):
    """
    Validation error that carries a dict compatible with DRF ValidationError.
    """
    def __init__(self, errors: dict[str, Any]):
        super().__init__("Patient validation error")
        self.errors = errors


class PatientMergeError(PatientServiceError):
    """Error during patient merge operation."""


def _raise(errors: dict[str, Any]) -> None:
    raise PatientValidationError(errors)


def _dj_errors_to_dict(exc: DjangoValidationError) -> dict[str, Any]:
    """
    Convert Django ValidationError into a clean dict usable by DRF serializers.
    """
    if hasattr(exc, "message_dict"):
        return exc.message_dict
    if hasattr(exc, "messages"):
        return {"detail": exc.messages}
    return {"detail": [str(exc)]}


# =========================
# Defaults (using model constants for consistency)
# =========================


def _get_default_acquisition_channel() -> AcquisitionChannel:
    """Get the default WALK_IN acquisition channel."""
    ch = AcquisitionChannel.objects.filter(
        code__iexact=AcquisitionChannel.CODE_WALK_IN, 
        is_active=True
    ).first()
    if not ch:
        _raise({
            "acquisition_channel": (
                f"Default acquisition channel '{AcquisitionChannel.CODE_WALK_IN}' is missing or inactive. "
                "Run the seed command or activate the default channel."
            )
        })
    return ch


def _get_default_patient_type() -> PatientType:
    """Get the default GENERAL patient type."""
    pt = PatientType.objects.filter(
        code__iexact=PatientType.CODE_GENERAL, 
        is_active=True
    ).first()
    if not pt:
        _raise({
            "patient_type": (
                f"Default patient type '{PatientType.CODE_GENERAL}' is missing or inactive. "
                "Run the seed command or activate the default patient type."
            )
        })
    return pt


# =========================
# Inputs
# =========================

@dataclass(frozen=True)
class ReferralInput:
    """
    Referral details used ONLY when acquisition channel is 'REFERRED'.

    Exactly one of:
    - referrer_patient_id
    - referrer_name
    """
    referrer_patient_id: Optional[UUID] = None
    referrer_name: Optional[str] = None


# =========================
# Helpers / Lookups
# =========================

def is_referred_channel(channel: Optional[AcquisitionChannel]) -> bool:
    return bool(channel and (channel.code or "").strip().upper() == "REFERRED")


def resolve_patient_type(
    *,
    patient_type_id: Optional[UUID] = None,
    patient_type_name: Optional[str] = None,
    patient_type_code: Optional[str] = None,
    allow_null: bool = False,
    default_if_missing: bool = True,
) -> Optional[PatientType]:
    """
    Resolve PatientType by UUID, code, or case-insensitive name.
    Only active PatientTypes are allowed.

    Priority: id > code > name

    Behavior:
    - If no input provided:
        - allow_null=True  -> returns None
        - allow_null=False -> returns default patient type (if default_if_missing=True), else error
    """
    if not patient_type_id and not patient_type_code and not patient_type_name:
        if allow_null:
            return None
        if default_if_missing:
            return _get_default_patient_type()
        _raise({"patient_type": "Patient type is required."})

    qs = PatientType.objects.filter(is_active=True)
    obj = None

    if patient_type_id:
        obj = qs.filter(id=patient_type_id).first()
    elif patient_type_code:
        normalized_code = (str(patient_type_code).strip().upper()
                          .replace("-", "_").replace(" ", "_"))
        obj = qs.filter(code__iexact=normalized_code).first()
    elif patient_type_name:
        obj = qs.filter(name__iexact=str(patient_type_name).strip()).first()

    if not obj:
        _raise({"patient_type": "Invalid or inactive patient type."})

    return obj


def _normalize_acquisition_code(value: str) -> str:
    """
    Accepts values like:
      - 'WALK_IN'
      - 'walk-in'
      - 'Walk in'
    And normalizes to 'WALK_IN'
    """
    s = (value or "").strip()
    if not s:
        return s
    s = s.replace("-", " ").replace("_", " ")
    s = "_".join(part for part in s.split() if part)
    return s.upper()


def resolve_acquisition_channel(
    *,
    acquisition_channel_id: Optional[UUID] = None,
    acquisition_channel_code: Optional[str] = None,
    allow_null: bool = False,
    default_if_missing: bool = True,
) -> Optional[AcquisitionChannel]:
    """
    Resolve AcquisitionChannel by UUID or stable code (case-insensitive).
    Only active channels are allowed.

    Behavior:
    - If no input provided:
        - allow_null=True  -> returns None
        - allow_null=False -> returns default WALK_IN (if default_if_missing=True), else error
    """
    qs = AcquisitionChannel.objects.filter(is_active=True)

    if acquisition_channel_id:
        ch = qs.filter(id=acquisition_channel_id).first()
        if not ch:
            _raise({"acquisition_channel": "Invalid or inactive acquisition channel."})
        return ch

    if acquisition_channel_code:
        code = _normalize_acquisition_code(str(acquisition_channel_code))
        ch = qs.filter(code__iexact=code).first()
        if not ch:
            _raise({"acquisition_channel": "Invalid or inactive acquisition channel code."})
        return ch

    if allow_null:
        return None

    if default_if_missing:
        return _get_default_acquisition_channel()

    _raise({"acquisition_channel": "Acquisition channel is required."})
    return None  # unreachable


def _normalize_str(v: Any) -> Any:
    if isinstance(v, str):
        s = v.strip()
        return s if s != "" else None
    return v


def _normalize_patient_payload(data: dict[str, Any]) -> dict[str, Any]:
    """
    Strip strings + convert empty strings to None to keep DB constraints happy.
    """
    clean: dict[str, Any] = {}
    for k, v in data.items():
        clean[k] = _normalize_str(v)

    # Normalize emails explicitly
    if clean.get("email"):
        clean["email"] = str(clean["email"]).strip().lower()
    if clean.get("guardian_email"):
        clean["guardian_email"] = str(clean["guardian_email"]).strip().lower()

    return clean


def _coerce_uuid(value: Any, field: str) -> UUID:
    if value is None or value == "":
        raise ValueError("empty")
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except Exception:
        _raise({field: f"Invalid UUID: {value}"})


def _parse_referral_input(referral: Any) -> Optional[ReferralInput]:
    """
    Accepts:
    - None
    - ReferralInput
    - dict { "referrer_patient_id": "...", "referrer_name": "..." }
    """
    if referral is None:
        return None
    if isinstance(referral, ReferralInput):
        return referral
    if isinstance(referral, dict):
        rpid = referral.get("referrer_patient_id")
        rname = referral.get("referrer_name")

        coerced_patient_id = None
        if rpid not in (None, ""):
            coerced_patient_id = _coerce_uuid(rpid, "referral.referrer_patient_id")

        rname_norm = _normalize_str(rname)
        return ReferralInput(
            referrer_patient_id=coerced_patient_id,
            referrer_name=rname_norm,
        )

    _raise({"referral": "Invalid referral payload."})
    return None


def _validate_referral_input(ref: ReferralInput) -> None:
    """
    Enforce: exactly one of referrer_patient_id or referrer_name.
    """
    has_patient = bool(ref.referrer_patient_id)
    has_name = bool(ref.referrer_name and str(ref.referrer_name).strip())

    if has_patient and has_name:
        _raise({"referral": "Provide either referrer_patient_id OR referrer_name, not both."})
    if not has_patient and not has_name:
        _raise({"referral": "Referral requires referrer_patient_id or referrer_name."})


def _upsert_referral_for_patient(patient: Patient, ref: ReferralInput) -> PatientReferral:
    """
    Create or update PatientReferral for a patient.
    """
    _validate_referral_input(ref)

    referrer_patient = None
    referrer_name = None

    if ref.referrer_patient_id:
        referrer_patient = Patient.objects.filter(id=ref.referrer_patient_id).first()
        if not referrer_patient:
            _raise({"referral": {"referrer_patient_id": "Referrer patient not found."}})
        if referrer_patient.id == patient.id:
            _raise({"referral": {"referrer_patient_id": "A patient cannot refer themselves."}})
    else:
        referrer_name = str(ref.referrer_name).strip()

    # Use update_or_create with defaults to satisfy the CHECK constraint
    obj, _ = PatientReferral.objects.update_or_create(
        patient=patient,
        defaults={
            "referrer_patient": referrer_patient,
            "referrer_name": referrer_name,
        },
    )

    try:
        obj.full_clean()
    except DjangoValidationError as e:
        _raise(_dj_errors_to_dict(e))

    return obj


def _delete_referral_if_exists(patient: Patient) -> None:
    PatientReferral.objects.filter(patient=patient).delete()


# =========================
# Public Services
# =========================

@transaction.atomic
def register_patient(*, payload: dict[str, Any], request=None) -> Patient:
    """
    Register a new patient (Digital Folder creation).

    Defaults:
    - patient_type defaults to GENERAL (by code, seeded)
    - acquisition_channel defaults to WALK_IN (seeded)

    Referral rules:
    - Referral details are required ONLY if acquisition_channel.code == 'REFERRED'
    - Referral details are NOT allowed for other channels
    
    Note: This function does NOT perform duplicate checking.
    For atomic duplicate checking + registration, use register_patient_with_duplicate_check().
    """
    return _register_patient_internal(payload=payload, request=request)


@transaction.atomic
def update_patient(*, patient: Patient, payload: dict[str, Any], request=None) -> Patient:
    """
    Update an existing patient with business rules enforced.

    Behavior:
    - patient_type and acquisition_channel remain required (defaults are NOT auto-applied on update)
      unless explicitly provided (i.e. we do not silently change them).
    - If acquisition_channel becomes REFERRED -> referral required (upsert if provided).
    - If acquisition_channel changes away from REFERRED -> referral deleted.
    - If is_child becomes False -> guardian fields are cleared (strict hygiene).
    """
    if not isinstance(payload, dict):
        _raise({"detail": "Payload must be an object/dict."})

    data = dict(payload)
    referral_raw = data.pop("referral", None)

    # Update patient_type if provided
    if "patient_type_id" in data or "patient_type_name" in data or "patient_type_code" in data:
        patient.patient_type = resolve_patient_type(
            patient_type_id=data.pop("patient_type_id", None),
            patient_type_name=data.pop("patient_type_name", None),
            patient_type_code=data.pop("patient_type_code", None),
            allow_null=False,
            default_if_missing=False,  # do not silently default on update
        )

    # Update acquisition channel if provided
    if "acquisition_channel_id" in data or "acquisition_channel_code" in data:
        patient.acquisition_channel = resolve_acquisition_channel(
            acquisition_channel_id=data.pop("acquisition_channel_id", None),
            acquisition_channel_code=data.pop("acquisition_channel_code", None),
            allow_null=False,
            default_if_missing=False,  # do not silently default on update
        )

    data = _normalize_patient_payload(data)

    # Apply updates
    for field, value in data.items():
        if field == "folder_number":
            continue
        setattr(patient, field, value)

    # If set to non-child, clear guardian fields
    if patient.is_child is False:
        patient.guardian_name = None
        patient.guardian_phone = None
        patient.guardian_occupation = None
        patient.guardian_address = None
        patient.guardian_email = None

    try:
        patient.full_clean()
        patient.save()
    except DjangoValidationError as e:
        _raise(_dj_errors_to_dict(e))

    ref = _parse_referral_input(referral_raw)

    if is_referred_channel(patient.acquisition_channel):
        if ref is None:
            # allow if referral already exists; require if none exists
            has_existing = PatientReferral.objects.filter(patient=patient).exists()
            if not has_existing:
                _raise({"referral": "Referral details are required when acquisition channel is REFERRED."})
        else:
            _upsert_referral_for_patient(patient, ref)
    else:
        if ref is not None:
            _raise({"referral": "Referral details are only allowed when acquisition channel is REFERRED."})
        _delete_referral_if_exists(patient)

    _log_patient_action("info", "Patient updated", patient.folder_number, str(patient.id))

    audit_log(
        action=PatientAuditAction.PATIENT_UPDATED,
        request=request,
        success=True,
        metadata={
            "patient_id": str(patient.id),
            "folder_number": patient.folder_number,
        },
    )

    return patient


@transaction.atomic
def soft_delete_patient(*, patient: Patient, request=None) -> Patient:
    """Soft delete a patient record (audit-friendly)."""
    deleted_by = None
    if request and hasattr(request, "user") and request.user.is_authenticated:
        deleted_by = request.user

    patient.soft_delete(deleted_by=deleted_by)

    _log_patient_action("warning", "Patient soft-deleted", patient.folder_number, str(patient.id))

    audit_log(
        action=PatientAuditAction.PATIENT_DELETED,
        request=request,
        success=True,
        metadata={
            "patient_id": str(patient.id),
            "folder_number": patient.folder_number,
        },
    )

    return patient


@transaction.atomic
def restore_patient(*, patient: Patient, request=None) -> Patient:
    """Restore a soft-deleted patient record."""
    patient.restore()

    _log_patient_action("info", "Patient restored", patient.folder_number, str(patient.id))

    audit_log(
        action=PatientAuditAction.PATIENT_RESTORED,
        request=request,
        success=True,
        metadata={
            "patient_id": str(patient.id),
            "folder_number": patient.folder_number,
        },
    )

    return patient


def compute_age_from_dob(dob) -> Optional[int]:
    """Compute age without requiring a Patient instance."""
    if not dob:
        return None
    today = timezone.localdate()
    years = today.year - dob.year
    if (today.month, today.day) < (dob.month, dob.day):
        years -= 1
    return max(years, 0)


# =========================
# Duplicate Detection
# =========================

@dataclass
class DuplicateMatch:
    patient: Patient
    score: int
    match_reasons: list[str]


def _normalize_name(name: Optional[str]) -> str:
    return (name or "").strip().lower()


def _normalize_phone(phone: Optional[str]) -> str:
    if not phone:
        return ""
    return "".join(c for c in str(phone) if c.isdigit())


def find_potential_duplicates(
    *,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    phone_number: Optional[str] = None,
    date_of_birth=None,
    email: Optional[str] = None,
    exclude_patient_id: Optional[UUID] = None,
    threshold: int = 30,
) -> list[DuplicateMatch]:
    """
    Find potential duplicate patients based on provided criteria.

    Scoring:
    - Phone match (last 9 digits): +50
    - Email exact match: +40
    - DOB + last name: +30
    - Exact first + last name: +30
    - Similar first name prefix (3 chars) + exact last name: +20
    - Same DOB only: +15
    """
    matches: dict[UUID, DuplicateMatch] = {}

    norm_first = _normalize_name(first_name)
    norm_last = _normalize_name(last_name)
    norm_phone = _normalize_phone(phone_number)
    norm_email = (email or "").strip().lower()

    base_qs = Patient.objects.all()
    if exclude_patient_id:
        base_qs = base_qs.exclude(id=exclude_patient_id)

    def add_match(patient: Patient, score: int, reason: str):
        if patient.id in matches:
            matches[patient.id].score += score
            matches[patient.id].match_reasons.append(reason)
        else:
            matches[patient.id] = DuplicateMatch(patient=patient, score=score, match_reasons=[reason])

    # 1) Phone match (last 9 digits)
    if norm_phone and len(norm_phone) >= 9:
        last9 = norm_phone[-9:]
        phone_matches = base_qs.filter(phone_number__endswith=last9)
        for p in phone_matches:
            add_match(p, 50, "Phone match (last 9 digits)")

    # 2) Email match
    if norm_email:
        for p in base_qs.filter(email__iexact=norm_email):
            add_match(p, 40, "Email exact match")

    # 3) DOB + last name
    if date_of_birth and norm_last:
        for p in base_qs.filter(date_of_birth=date_of_birth, last_name__iexact=norm_last):
            add_match(p, 30, "Same DOB + last name")

    # 4) Exact first + last name
    if norm_first and norm_last:
        for p in base_qs.filter(first_name__iexact=norm_first, last_name__iexact=norm_last):
            add_match(p, 30, "Exact first + last name")

    # 5) Similar first name prefix + exact last name
    if norm_first and norm_last and len(norm_first) >= 3:
        for p in base_qs.filter(first_name__istartswith=norm_first[:3], last_name__iexact=norm_last).exclude(
            first_name__iexact=norm_first
        ):
            add_match(p, 20, f"Similar first name ({p.first_name}) + same last name")

    # 6) Same DOB only
    if date_of_birth:
        for p in base_qs.filter(date_of_birth=date_of_birth):
            add_match(p, 15, "Same DOB")

    results = [m for m in matches.values() if m.score >= threshold]
    results.sort(key=lambda x: x.score, reverse=True)
    return results


def find_duplicates_for_patient(patient: Patient, threshold: int = 30) -> list[DuplicateMatch]:
    return find_potential_duplicates(
        first_name=patient.first_name,
        last_name=patient.last_name,
        phone_number=patient.phone_number,
        date_of_birth=patient.date_of_birth,
        email=patient.email,
        exclude_patient_id=patient.id,
        threshold=threshold,
    )


def _find_duplicates_with_lock(
    *,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    phone_number: Optional[str] = None,
    date_of_birth=None,
    email: Optional[str] = None,
    threshold: int = 30,
) -> list[DuplicateMatch]:
    """
    Find potential duplicates with row-level locking to prevent race conditions.
    
    This function MUST be called within a transaction.atomic() block.
    It locks matching rows to prevent concurrent inserts of duplicates.
    
    The locking strategy:
    1. Lock patients matching the phone number (highest priority match)
    2. Lock patients matching email (if provided)
    3. Lock patients matching DOB + last name combination
    
    This prevents the race condition where two concurrent requests
    both check for duplicates, find none, and both create the same patient.
    """
    matches: dict[UUID, DuplicateMatch] = {}
    
    norm_first = _normalize_name(first_name)
    norm_last = _normalize_name(last_name)
    norm_phone = _normalize_phone(phone_number)
    norm_email = (email or "").strip().lower()
    
    def add_match(patient: Patient, score: int, reason: str):
        if patient.id in matches:
            matches[patient.id].score += score
            matches[patient.id].match_reasons.append(reason)
        else:
            matches[patient.id] = DuplicateMatch(patient=patient, score=score, match_reasons=[reason])
    
    # Lock and check phone matches (highest priority - most likely duplicate)
    if norm_phone and len(norm_phone) >= 9:
        last9 = norm_phone[-9:]
        # select_for_update locks these rows until transaction completes
        phone_matches = list(
            Patient.objects.select_for_update(nowait=False)
            .filter(phone_number__endswith=last9)
        )
        for p in phone_matches:
            add_match(p, 50, "Phone match (last 9 digits)")
    
    # Lock and check email matches
    if norm_email:
        email_matches = list(
            Patient.objects.select_for_update(nowait=False)
            .filter(email__iexact=norm_email)
        )
        for p in email_matches:
            add_match(p, 40, "Email exact match")
    
    # Lock and check DOB + last name (common duplicate pattern)
    if date_of_birth and norm_last:
        dob_name_matches = list(
            Patient.objects.select_for_update(nowait=False)
            .filter(date_of_birth=date_of_birth, last_name__iexact=norm_last)
        )
        for p in dob_name_matches:
            add_match(p, 30, "Same DOB + last name")
    
    # Check exact name match (lock if combined with other criteria)
    if norm_first and norm_last:
        name_matches = list(
            Patient.objects.select_for_update(nowait=False)
            .filter(first_name__iexact=norm_first, last_name__iexact=norm_last)
        )
        for p in name_matches:
            add_match(p, 30, "Exact first + last name")
    
    results = [m for m in matches.values() if m.score >= threshold]
    results.sort(key=lambda x: x.score, reverse=True)
    return results


@dataclass
class DuplicateCheckResult:
    """Result of atomic duplicate check during registration."""
    has_duplicates: bool
    duplicates: list[DuplicateMatch]
    created_patient: Optional[Patient] = None


@transaction.atomic
def register_patient_with_duplicate_check(
    *,
    payload: dict[str, Any],
    duplicate_threshold: int = 50,
    skip_if_duplicate: bool = False,
    request=None,
) -> DuplicateCheckResult:
    """
    Atomically check for duplicates and register a patient.
    
    This function solves the race condition by:
    1. Acquiring row locks on potential duplicate patients
    2. Checking for duplicates while holding locks
    3. Either creating the patient or returning duplicates
    
    The entire operation is wrapped in a transaction, so:
    - If duplicates are found, no patient is created
    - If no duplicates exist, the patient is created atomically
    - Concurrent requests will wait for the lock and see the newly created patient
    
    Args:
        payload: Patient data for registration
        duplicate_threshold: Score threshold for duplicate detection (default 50)
        skip_if_duplicate: If True, return duplicates without raising error
        request: Django request object for audit logging
        
    Returns:
        DuplicateCheckResult with duplicates list and/or created patient
        
    Raises:
        PatientValidationError: If duplicates found and skip_if_duplicate=False
    """
    # Extract duplicate check fields from payload
    first_name = payload.get("first_name")
    last_name = payload.get("last_name")
    phone_number = payload.get("phone_number")
    date_of_birth = payload.get("date_of_birth")
    email = payload.get("email")
    
    # Find duplicates with locking (this acquires row locks)
    duplicates = _find_duplicates_with_lock(
        first_name=first_name,
        last_name=last_name,
        phone_number=phone_number,
        date_of_birth=date_of_birth,
        email=email,
        threshold=duplicate_threshold,
    )
    
    if duplicates:
        if skip_if_duplicate:
            return DuplicateCheckResult(
                has_duplicates=True,
                duplicates=duplicates,
                created_patient=None,
            )
        # Raise error with duplicate info (but no PII in message)
        top = duplicates[0]
        _raise({
            "duplicate_detected": (
                f"Potential duplicate found (folder={top.patient.folder_number}, "
                f"score={top.score}). Use force_create=true to override."
            )
        })
    
    # No duplicates found - safe to create (we hold locks on similar records)
    # Call the internal registration logic
    patient = _register_patient_internal(payload=payload, request=request)
    
    return DuplicateCheckResult(
        has_duplicates=False,
        duplicates=[],
        created_patient=patient,
    )


def _register_patient_internal(*, payload: dict[str, Any], request=None) -> Patient:
    """
    Internal patient registration logic (extracted from register_patient).
    
    This is called from both register_patient (no duplicate check)
    and register_patient_with_duplicate_check (with atomic duplicate check).
    
    MUST be called within a transaction.
    """
    if not isinstance(payload, dict):
        _raise({"detail": "Payload must be an object/dict."})

    data = dict(payload)
    referral_raw = data.pop("referral", None)

    patient_type = resolve_patient_type(
        patient_type_id=data.pop("patient_type_id", None),
        patient_type_name=data.pop("patient_type_name", None),
        patient_type_code=data.pop("patient_type_code", None),
        allow_null=False,
        default_if_missing=True,
    )

    acquisition_channel = resolve_acquisition_channel(
        acquisition_channel_id=data.pop("acquisition_channel_id", None),
        acquisition_channel_code=data.pop("acquisition_channel_code", None),
        allow_null=False,
        default_if_missing=True,
    )

    data = _normalize_patient_payload(data)

    patient = Patient(**data)
    patient.patient_type = patient_type
    patient.acquisition_channel = acquisition_channel

    try:
        patient.full_clean()
        patient.save()
    except DjangoValidationError as e:
        _raise(_dj_errors_to_dict(e))

    ref = _parse_referral_input(referral_raw)
    if is_referred_channel(acquisition_channel):
        if ref is None:
            _raise({"referral": "Referral details are required when acquisition channel is REFERRED."})
        _upsert_referral_for_patient(patient, ref)
    else:
        if ref is not None:
            _raise({"referral": "Referral details are only allowed when acquisition channel is REFERRED."})
        _delete_referral_if_exists(patient)

    _log_patient_action("info", "Patient registered", patient.folder_number, str(patient.id))

    audit_log(
        action=PatientAuditAction.PATIENT_CREATED,
        request=request,
        success=True,
        metadata={
            "patient_id": str(patient.id),
            "folder_number": patient.folder_number,
        },
    )

    return patient


# =========================
# Patient Merge
# =========================

def _patient_to_snapshot(patient: Patient) -> dict[str, Any]:
    return {
        "id": str(patient.id),
        "folder_number": patient.folder_number,
        "first_name": patient.first_name,
        "last_name": patient.last_name,
        "date_of_birth": str(patient.date_of_birth) if patient.date_of_birth else None,
        "gender": patient.gender,
        "phone_number": patient.phone_number,
        "email": patient.email,
        "occupation": patient.occupation,
        "address": patient.address,
        "nationality": patient.nationality,
        "is_child": patient.is_child,
        "guardian_name": patient.guardian_name,
        "guardian_phone": patient.guardian_phone,
        "guardian_occupation": patient.guardian_occupation,
        "guardian_address": patient.guardian_address,
        "guardian_email": patient.guardian_email,
        "patient_type_id": str(patient.patient_type_id) if patient.patient_type_id else None,
        "acquisition_channel_id": str(patient.acquisition_channel_id) if patient.acquisition_channel_id else None,
        "profile_picture_url": patient.profile_picture_url,
        "created_at": patient.created_at.isoformat() if patient.created_at else None,
    }


@transaction.atomic
def merge_patients(
    *,
    primary_patient: Patient,
    secondary_patient: Patient,
    merge_fields: Optional[list[str]] = None,
    merge_reason: str = "",
    request=None,
) -> Patient:
    """
    Merge two patient records into one.
    Primary is kept, secondary is soft-deleted.
    Transfers referral references where needed.
    """
    from ..models import PatientMergeHistory  # local import to avoid circular issues

    if primary_patient.id == secondary_patient.id:
        raise PatientMergeError("Cannot merge a patient with itself.")
    if primary_patient.is_deleted:
        raise PatientMergeError("Primary patient is deleted. Restore it first.")
    if secondary_patient.is_deleted:
        raise PatientMergeError("Secondary patient is already deleted.")

    secondary_snapshot = _patient_to_snapshot(secondary_patient)

    fields_updated: list[str] = []
    related_records_transferred: dict[str, Any] = {}

    mergeable_fields = [
        "email",
        "occupation",
        "address",
        "nationality",
        "profile_picture_url",
        "guardian_occupation",
        "guardian_address",
        "guardian_email",
    ]
    if merge_fields:
        mergeable_fields = [f for f in merge_fields if f in mergeable_fields]

    # Copy empty primary fields from secondary
    for field in mergeable_fields:
        pv = getattr(primary_patient, field, None)
        sv = getattr(secondary_patient, field, None)
        if not pv and sv:
            setattr(primary_patient, field, sv)
            fields_updated.append(field)

    if fields_updated:
        primary_patient.save()

    # Transfer "referrer_patient" references (patients referred by secondary)
    referrals_transferred = 0
    for ref in PatientReferral.objects.filter(referrer_patient=secondary_patient):
        ref.referrer_patient = primary_patient
        ref.save(update_fields=["referrer_patient", "updated_at"])
        referrals_transferred += 1
    if referrals_transferred:
        related_records_transferred["referrals_as_referrer"] = referrals_transferred

    # Transfer secondary's own referral record to primary if primary doesn't have one
    primary_has_ref = PatientReferral.objects.filter(patient=primary_patient).exists()
    try:
        secondary_ref = PatientReferral.objects.get(patient=secondary_patient)
        if not primary_has_ref:
            secondary_ref.patient = primary_patient
            secondary_ref.save(update_fields=["patient", "updated_at"])
            related_records_transferred["referral_transferred"] = True
        else:
            secondary_ref.delete()
            related_records_transferred["referral_deleted"] = True
    except PatientReferral.DoesNotExist:
        pass

    merged_by = None
    if request and hasattr(request, "user") and request.user.is_authenticated:
        merged_by = request.user

    merge_history = PatientMergeHistory.objects.create(
        primary_patient=primary_patient,
        secondary_patient_id=secondary_patient.id,
        secondary_folder_number=secondary_patient.folder_number,
        secondary_patient_snapshot=secondary_snapshot,
        merged_by=merged_by,
        merge_reason=merge_reason,
        fields_updated=fields_updated,
        related_records_transferred=related_records_transferred,
    )

    secondary_patient.soft_delete(deleted_by=merged_by)

    _log_patient_action(
        "info",
        f"Patient merge completed (secondary folder={secondary_patient.folder_number})",
        primary_patient.folder_number,
        str(primary_patient.id),
    )

    audit_log(
        action=PatientAuditAction.PATIENT_MERGED,
        request=request,
        success=True,
        metadata={
            "primary_patient_id": str(primary_patient.id),
            "primary_folder_number": primary_patient.folder_number,
            "secondary_patient_id": str(secondary_patient.id),
            "secondary_folder_number": secondary_patient.folder_number,
            "fields_updated": fields_updated,
            "merge_history_id": str(merge_history.id),
            "related_records_transferred": related_records_transferred,
        },
    )

    return primary_patient


def get_merge_history(patient: Patient) -> list:
    """Return merge history where patient was primary or secondary."""
    from ..models import PatientMergeHistory

    as_primary = list(PatientMergeHistory.objects.filter(primary_patient=patient).order_by("-created_at"))
    as_secondary = list(PatientMergeHistory.objects.filter(secondary_patient_id=patient.id).order_by("-created_at"))

    all_history = as_primary + as_secondary
    all_history.sort(key=lambda x: x.created_at, reverse=True)
    return all_history
