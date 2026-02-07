"""
Tests for Patient Models.

Tests the Patient, PatientType, AcquisitionChannel, and PatientReferral models.
"""
import uuid
from datetime import date, timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from patients.models import (
    AcquisitionChannel,
    Gender,
    Patient,
    PatientFolderCounter,
    PatientReferral,
    PatientType,
)


class PatientTypeModelTests(TestCase):
    """Tests for PatientType model."""

    def test_create_patient_type(self):
        """Test creating a patient type."""
        pt = PatientType.objects.create(
            name="Regular",
            description="Default patient category",
            is_active=True,
        )
        self.assertIsInstance(pt.id, uuid.UUID)
        self.assertEqual(str(pt), "Regular")
        self.assertTrue(pt.is_active)

    def test_patient_type_name_uniqueness(self):
        """Test that patient type names must be unique."""
        PatientType.objects.create(name="VIP")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                PatientType.objects.create(name="VIP")


class AcquisitionChannelModelTests(TestCase):
    """Tests for AcquisitionChannel model."""

    def test_create_acquisition_channel(self):
        """Test creating an acquisition channel."""
        ch = AcquisitionChannel.objects.create(
            code="REFERRED",
            name="Referred",
            description="Patient was referred",
        )
        self.assertIsInstance(ch.id, uuid.UUID)
        self.assertEqual(str(ch), "Referred")

    def test_get_default_referred(self):
        """Test getting the default REFERRED channel."""
        AcquisitionChannel.objects.create(
            code="REFERRED",
            name="Referred",
            is_active=True,
        )
        default = AcquisitionChannel.get_default_referred()
        self.assertIsNotNone(default)
        self.assertEqual(default.code, "REFERRED")

    def test_get_default_referred_returns_none_if_missing(self):
        """Test that get_default_referred returns None if not seeded."""
        default = AcquisitionChannel.get_default_referred()
        self.assertIsNone(default)


class PatientFolderCounterModelTests(TestCase):
    """Tests for PatientFolderCounter model."""

    def test_counter_increments(self):
        """Test that counter increments correctly."""
        year = timezone.localdate().year
        counter, _ = PatientFolderCounter.objects.get_or_create(year=year)
        original = counter.last_sequence
        counter.last_sequence += 1
        counter.save()
        counter.refresh_from_db()
        self.assertEqual(counter.last_sequence, original + 1)


class PatientModelTests(TestCase):
    """Tests for Patient model."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
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

    def test_create_adult_patient(self):
        """Test creating an adult patient."""
        patient = Patient(
            first_name="Kofi",
            last_name="Mensah",
            date_of_birth=date(1990, 5, 15),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )
        patient.full_clean()
        patient.save()

        self.assertIsNotNone(patient.folder_number)
        self.assertTrue(patient.folder_number.startswith("DEN-"))
        self.assertEqual(patient.full_name, "Kofi Mensah")
        self.assertIsNotNone(patient.age)

    def test_create_child_patient_requires_guardian(self):
        """Test that child patients require guardian information."""
        patient = Patient(
            first_name="Ama",
            last_name="Mensah",
            date_of_birth=date(2020, 1, 1),
            gender=Gender.FEMALE,
            phone_number="+233241234567",
            is_child=True,
            acquisition_channel=self.walk_in_channel,
            # Missing guardian info
        )
        with self.assertRaises(ValidationError) as ctx:
            patient.full_clean()
        self.assertIn("guardian_name", str(ctx.exception))

    def test_create_child_patient_with_guardian(self):
        """Test creating a child patient with guardian information."""
        patient = Patient(
            first_name="Ama",
            last_name="Mensah",
            date_of_birth=date(2020, 1, 1),
            gender=Gender.FEMALE,
            phone_number="+233241234567",
            is_child=True,
            guardian_name="Kofi Mensah",
            guardian_phone="+233241234568",
            acquisition_channel=self.walk_in_channel,
        )
        patient.full_clean()
        patient.save()
        self.assertIsNotNone(patient.folder_number)

    def test_adult_patient_cannot_have_guardian_fields(self):
        """Test that adult patients cannot have guardian fields."""
        patient = Patient(
            first_name="Kofi",
            last_name="Mensah",
            date_of_birth=date(1990, 5, 15),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            guardian_name="Should Not Be Set",  # Invalid for adult
            acquisition_channel=self.walk_in_channel,
        )
        with self.assertRaises(ValidationError):
            patient.full_clean()

    def test_folder_number_is_immutable(self):
        """Test that folder_number cannot be changed after creation."""
        patient = Patient.objects.create(
            first_name="Kofi",
            last_name="Mensah",
            date_of_birth=date(1990, 5, 15),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )
        original_folder = patient.folder_number
        patient.folder_number = "DEN-9999-999"
        with self.assertRaises(ValueError):
            patient.save()

    def test_folder_number_format(self):
        """Test that folder_number follows the expected format."""
        patient = Patient.objects.create(
            first_name="Kofi",
            last_name="Mensah",
            date_of_birth=date(1990, 5, 15),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )
        year = timezone.localdate().year
        self.assertRegex(patient.folder_number, rf"^DEN-{year}-\d{{3}}$")

    def test_age_calculation(self):
        """Test age property calculation."""
        today = timezone.localdate()
        dob = today - timedelta(days=365 * 30)  # Approximately 30 years ago
        patient = Patient(
            first_name="Test",
            last_name="Patient",
            date_of_birth=dob,
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
        )
        # Age should be approximately 30 (might be 29 or 30 depending on exact dates)
        self.assertIn(patient.age, [29, 30])

    def test_phone_number_validation(self):
        """Test that phone numbers must be in Ghana format."""
        patient = Patient(
            first_name="Test",
            last_name="Patient",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            phone_number="1234567890",  # Invalid format
            is_child=False,
        )
        with self.assertRaises(ValidationError):
            patient.full_clean()

    def test_email_normalization(self):
        """Test that email is normalized to lowercase."""
        patient = Patient.objects.create(
            first_name="Test",
            last_name="Patient",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            phone_number="+233241234567",
            email="TEST@EXAMPLE.COM",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )
        self.assertEqual(patient.email, "test@example.com")


class PatientReferralModelTests(TestCase):
    """Tests for PatientReferral model."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
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
        """Helper to create a patient."""
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

    def test_create_referral_with_existing_patient(self):
        """Test creating a referral with an existing patient as referrer."""
        referrer = self._create_patient(
            first_name="Referrer",
            phone_number="+233241234568",
        )
        patient = self._create_patient(
            first_name="Referred",
            phone_number="+233241234569",
        )
        
        referral = PatientReferral.objects.create(
            patient=patient,
            referrer_patient=referrer,
        )
        self.assertIsNotNone(referral.id)
        self.assertEqual(referral.referrer_patient, referrer)
        self.assertIsNone(referral.referrer_name)

    def test_create_referral_with_external_name(self):
        """Test creating a referral with an external referrer name."""
        patient = self._create_patient()
        
        referral = PatientReferral.objects.create(
            patient=patient,
            referrer_name="Dr. External",
        )
        self.assertIsNotNone(referral.id)
        self.assertIsNone(referral.referrer_patient)
        self.assertEqual(referral.referrer_name, "Dr. External")

    def test_referral_requires_exactly_one_referrer_source(self):
        """Test that referral requires exactly one of referrer_patient or referrer_name."""
        patient = self._create_patient()
        
        # Neither provided
        referral = PatientReferral(patient=patient)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                referral.save()

    def test_patient_cannot_refer_themselves(self):
        """Test that a patient cannot refer themselves."""
        patient = self._create_patient()
        
        referral = PatientReferral(
            patient=patient,
            referrer_patient=patient,  # Self-referral
        )
        with self.assertRaises(ValidationError):
            referral.full_clean()
