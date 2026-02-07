"""
Tests for Patient Services.

Tests the register_patient and update_patient service functions.
"""
from datetime import date

from django.test import TestCase

from patients.models import (
    AcquisitionChannel,
    Gender,
    Patient,
    PatientReferral,
    PatientType,
)
from patients.services.patients import (
    PatientValidationError,
    compute_age_from_dob,
    is_referred_channel,
    register_patient,
    register_patient_with_duplicate_check,
    resolve_acquisition_channel,
    resolve_patient_type,
    update_patient,
)


class ResolverFunctionTests(TestCase):
    """Tests for resolver helper functions."""

    @classmethod
    def setUpTestData(cls):
        cls.active_type = PatientType.objects.create(
            name="Regular",
            is_active=True,
        )
        cls.inactive_type = PatientType.objects.create(
            name="Archived",
            is_active=False,
        )
        cls.referred_channel = AcquisitionChannel.objects.create(
            code="REFERRED",
            name="Referred",
            is_active=True,
        )
        cls.walk_in_channel = AcquisitionChannel.objects.create(
            code="WALK_IN",
            name="Walk-in",
            is_active=True,
        )

    def test_resolve_patient_type_by_id(self):
        """Test resolving patient type by UUID."""
        result = resolve_patient_type(patient_type_id=self.active_type.id)
        self.assertEqual(result, self.active_type)

    def test_resolve_patient_type_by_name(self):
        """Test resolving patient type by name (case-insensitive)."""
        result = resolve_patient_type(patient_type_name="REGULAR")
        self.assertEqual(result, self.active_type)

    def test_resolve_patient_type_inactive_fails(self):
        """Test that inactive patient types cannot be resolved."""
        with self.assertRaises(PatientValidationError):
            resolve_patient_type(patient_type_id=self.inactive_type.id)

    def test_resolve_acquisition_channel_by_code(self):
        """Test resolving acquisition channel by code."""
        result = resolve_acquisition_channel(acquisition_channel_code="walk_in")
        self.assertEqual(result, self.walk_in_channel)

    def test_is_referred_channel(self):
        """Test is_referred_channel helper."""
        self.assertTrue(is_referred_channel(self.referred_channel))
        self.assertFalse(is_referred_channel(self.walk_in_channel))
        self.assertFalse(is_referred_channel(None))


class RegisterPatientServiceTests(TestCase):
    """Tests for register_patient service function."""

    @classmethod
    def setUpTestData(cls):
        cls.referred_channel = AcquisitionChannel.objects.create(
            code="REFERRED",
            name="Referred",
            is_active=True,
        )
        cls.walk_in_channel = AcquisitionChannel.objects.create(
            code="WALK_IN",
            name="Walk-in",
            is_active=True,
        )
        cls.patient_type = PatientType.objects.create(
            name="Regular",
            is_active=True,
        )

    def test_register_adult_patient(self):
        """Test registering an adult patient."""
        payload = {
            "first_name": "Kofi",
            "last_name": "Mensah",
            "date_of_birth": date(1990, 5, 15),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "WALK_IN",
        }
        patient = register_patient(payload=payload)
        
        self.assertIsNotNone(patient.id)
        self.assertIsNotNone(patient.folder_number)
        self.assertEqual(patient.first_name, "Kofi")
        self.assertEqual(patient.acquisition_channel, self.walk_in_channel)

    def test_register_child_patient_with_guardian(self):
        """Test registering a child patient with guardian."""
        payload = {
            "first_name": "Ama",
            "last_name": "Mensah",
            "date_of_birth": date(2020, 1, 1),
            "gender": Gender.FEMALE,
            "phone_number": "+233241234567",
            "is_child": True,
            "guardian_name": "Kofi Mensah",
            "guardian_phone": "+233241234568",
            "acquisition_channel_code": "WALK_IN",
        }
        patient = register_patient(payload=payload)
        
        self.assertTrue(patient.is_child)
        self.assertEqual(patient.guardian_name, "Kofi Mensah")

    def test_register_child_without_guardian_fails(self):
        """Test that registering a child without guardian fails."""
        payload = {
            "first_name": "Ama",
            "last_name": "Mensah",
            "date_of_birth": date(2020, 1, 1),
            "gender": Gender.FEMALE,
            "phone_number": "+233241234567",
            "is_child": True,
            "acquisition_channel_code": "WALK_IN",
        }
        with self.assertRaises(PatientValidationError) as ctx:
            register_patient(payload=payload)
        self.assertIn("guardian", str(ctx.exception.errors).lower())

    def test_register_referred_patient_requires_referral(self):
        """Test that referred patients require referral details."""
        payload = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "REFERRED",
            # Missing referral
        }
        with self.assertRaises(PatientValidationError) as ctx:
            register_patient(payload=payload)
        self.assertIn("referral", str(ctx.exception.errors).lower())

    def test_register_referred_patient_with_external_referrer(self):
        """Test registering a referred patient with external referrer name."""
        payload = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "REFERRED",
            "referral": {
                "referrer_name": "Dr. External Dentist",
            },
        }
        patient = register_patient(payload=payload)
        
        self.assertTrue(hasattr(patient, "referral"))
        self.assertEqual(patient.referral.referrer_name, "Dr. External Dentist")

    def test_register_referred_patient_with_existing_patient_referrer(self):
        """Test registering a referred patient with existing patient as referrer."""
        referrer = Patient.objects.create(
            first_name="Referrer",
            last_name="Patient",
            date_of_birth=date(1985, 1, 1),
            gender=Gender.MALE,
            phone_number="+233241234568",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )
        
        payload = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "REFERRED",
            "referral": {
                "referrer_patient_id": str(referrer.id),
            },
        }
        patient = register_patient(payload=payload)
        
        self.assertEqual(patient.referral.referrer_patient, referrer)

    def test_non_referred_patient_cannot_have_referral(self):
        """Test that non-referred patients cannot have referral details."""
        payload = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "WALK_IN",
            "referral": {
                "referrer_name": "Should Not Be Allowed",
            },
        }
        with self.assertRaises(PatientValidationError):
            register_patient(payload=payload)


class UpdatePatientServiceTests(TestCase):
    """Tests for update_patient service function."""

    @classmethod
    def setUpTestData(cls):
        cls.referred_channel = AcquisitionChannel.objects.create(
            code="REFERRED",
            name="Referred",
            is_active=True,
        )
        cls.walk_in_channel = AcquisitionChannel.objects.create(
            code="WALK_IN",
            name="Walk-in",
            is_active=True,
        )

    def _create_patient(self, **kwargs):
        defaults = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel": self.walk_in_channel,
        }
        defaults.update(kwargs)
        return Patient.objects.create(**defaults)

    def test_update_basic_fields(self):
        """Test updating basic patient fields."""
        patient = self._create_patient()
        
        updated = update_patient(
            patient=patient,
            payload={"first_name": "Updated", "last_name": "Name"},
        )
        
        self.assertEqual(updated.first_name, "Updated")
        self.assertEqual(updated.last_name, "Name")

    def test_update_folder_number_is_ignored(self):
        """Test that folder_number updates are silently ignored."""
        patient = self._create_patient()
        original_folder = patient.folder_number
        
        updated = update_patient(
            patient=patient,
            payload={"folder_number": "DEN-9999-999"},
        )
        
        self.assertEqual(updated.folder_number, original_folder)

    def test_change_to_referred_requires_referral(self):
        """Test that changing to REFERRED channel requires referral details."""
        patient = self._create_patient()
        
        with self.assertRaises(PatientValidationError):
            update_patient(
                patient=patient,
                payload={"acquisition_channel_code": "REFERRED"},
            )

    def test_change_from_referred_deletes_referral(self):
        """Test that changing from REFERRED channel deletes the referral."""
        patient = self._create_patient(acquisition_channel=self.referred_channel)
        PatientReferral.objects.create(
            patient=patient,
            referrer_name="External Referrer",
        )
        
        updated = update_patient(
            patient=patient,
            payload={"acquisition_channel_code": "WALK_IN"},
        )
        
        self.assertFalse(PatientReferral.objects.filter(patient=patient).exists())

    def test_change_to_adult_clears_guardian_fields(self):
        """Test that changing is_child to False clears guardian fields."""
        patient = self._create_patient(
            is_child=True,
            guardian_name="Guardian",
            guardian_phone="+233241234568",
        )
        
        updated = update_patient(
            patient=patient,
            payload={"is_child": False},
        )
        
        self.assertFalse(updated.is_child)
        self.assertIsNone(updated.guardian_name)
        self.assertIsNone(updated.guardian_phone)


class ComputeAgeTests(TestCase):
    """Tests for age computation utility."""

    def test_compute_age_from_dob(self):
        """Test age computation from date of birth."""
        from django.utils import timezone
        
        today = timezone.localdate()
        dob = today.replace(year=today.year - 30)
        
        age = compute_age_from_dob(dob)
        self.assertEqual(age, 30)

    def test_compute_age_from_none(self):
        """Test age computation with None DOB."""
        age = compute_age_from_dob(None)
        self.assertIsNone(age)


class AtomicDuplicateCheckTests(TestCase):
    """Tests for atomic duplicate detection during registration."""

    @classmethod
    def setUpTestData(cls):
        cls.walk_in_channel = AcquisitionChannel.objects.create(
            code="WALK_IN",
            name="Walk-in",
            is_active=True,
        )
        cls.patient_type = PatientType.objects.create(
            code="GENERAL",
            name="General",
            is_active=True,
        )

    def test_register_with_duplicate_check_creates_patient(self):
        """Test that registration works when no duplicates exist."""
        payload = {
            "first_name": "Unique",
            "last_name": "Patient",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",
            "is_child": False,
        }
        
        result = register_patient_with_duplicate_check(
            payload=payload,
            duplicate_threshold=50,
            skip_if_duplicate=False,
        )
        
        self.assertFalse(result.has_duplicates)
        self.assertEqual(result.duplicates, [])
        self.assertIsNotNone(result.created_patient)
        self.assertEqual(result.created_patient.first_name, "Unique")

    def test_register_detects_phone_duplicate(self):
        """Test that registration detects phone number duplicates."""
        # Create existing patient
        existing = Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1985, 5, 15),
            gender=Gender.FEMALE,
            phone_number="+233241234567",
            is_child=False,
            patient_type=self.patient_type,
            acquisition_channel=self.walk_in_channel,
        )
        
        payload = {
            "first_name": "New",
            "last_name": "Person",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234567",  # Same phone
            "is_child": False,
        }
        
        # Should raise error when skip_if_duplicate=False
        with self.assertRaises(PatientValidationError) as ctx:
            register_patient_with_duplicate_check(
                payload=payload,
                duplicate_threshold=50,
                skip_if_duplicate=False,
            )
        self.assertIn("duplicate", str(ctx.exception.errors).lower())

    def test_register_skips_on_duplicate_when_configured(self):
        """Test that registration skips when skip_if_duplicate=True."""
        # Create existing patient
        existing = Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1985, 5, 15),
            gender=Gender.FEMALE,
            phone_number="+233241234568",
            is_child=False,
            patient_type=self.patient_type,
            acquisition_channel=self.walk_in_channel,
        )
        
        payload = {
            "first_name": "New",
            "last_name": "Person",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233241234568",  # Same phone
            "is_child": False,
        }
        
        result = register_patient_with_duplicate_check(
            payload=payload,
            duplicate_threshold=50,
            skip_if_duplicate=True,  # Skip instead of error
        )
        
        self.assertTrue(result.has_duplicates)
        self.assertIsNone(result.created_patient)
        self.assertEqual(len(result.duplicates), 1)
        self.assertEqual(result.duplicates[0].patient.id, existing.id)

    def test_register_allows_different_phone(self):
        """Test that registration allows patients with different phones."""
        # Create existing patient
        Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1985, 5, 15),
            gender=Gender.FEMALE,
            phone_number="+233241234567",
            is_child=False,
            patient_type=self.patient_type,
            acquisition_channel=self.walk_in_channel,
        )
        
        payload = {
            "first_name": "New",
            "last_name": "Person",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233249999999",  # Different phone
            "is_child": False,
        }
        
        result = register_patient_with_duplicate_check(
            payload=payload,
            duplicate_threshold=50,
            skip_if_duplicate=False,
        )
        
        self.assertFalse(result.has_duplicates)
        self.assertIsNotNone(result.created_patient)

    def test_register_detects_email_duplicate(self):
        """Test that registration detects email duplicates."""
        # Create existing patient
        Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1985, 5, 15),
            gender=Gender.FEMALE,
            phone_number="+233241234567",
            email="test@example.com",
            is_child=False,
            patient_type=self.patient_type,
            acquisition_channel=self.walk_in_channel,
        )
        
        payload = {
            "first_name": "New",
            "last_name": "Person",
            "date_of_birth": date(1990, 1, 1),
            "gender": Gender.MALE,
            "phone_number": "+233249999999",  # Different phone
            "email": "test@example.com",  # Same email
            "is_child": False,
        }
        
        result = register_patient_with_duplicate_check(
            payload=payload,
            duplicate_threshold=40,  # Email match is 40 points
            skip_if_duplicate=True,
        )
        
        self.assertTrue(result.has_duplicates)
        self.assertIn("Email", result.duplicates[0].match_reasons[0])

