"""
Tests for Patient Views.

Tests the Patient API endpoints.
"""
from datetime import date

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import CustomUser, UserRole
from patients.models import (
    AcquisitionChannel,
    Gender,
    Patient,
    PatientReferral,
    PatientType,
)


class PatientViewTestMixin:
    """Mixin providing common setup for patient view tests."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        # Create users with different roles
        cls.admin_user = CustomUser.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            user_role=UserRole.ADMIN,
            first_name="Admin",
            last_name="User",
        )
        cls.secretary_user = CustomUser.objects.create_user(
            email="secretary@test.com",
            password="testpass123",
            user_role=UserRole.SECRETARY,
            first_name="Secretary",
            last_name="User",
        )
        cls.dentist_user = CustomUser.objects.create_user(
            email="dentist@test.com",
            password="testpass123",
            user_role=UserRole.DENTIST,
            first_name="Dentist",
            last_name="User",
        )

        # Create lookup data
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


class PatientListCreateViewTests(PatientViewTestMixin, APITestCase):
    """Tests for patient list and create endpoints."""

    def test_list_patients_requires_authentication(self):
        """Test that unauthenticated users cannot list patients."""
        url = reverse("patients:patient-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_patients_as_authenticated_user(self):
        """Test that authenticated users can list patients."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:patient-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_patient_requires_front_desk_role(self):
        """Test that only front desk staff can create patients."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:patient-list-create")
        data = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": "1990-01-01",
            "gender": "Male",
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "WALK_IN",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_patient_as_secretary(self):
        """Test that secretary can create patients."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:patient-list-create")
        data = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": "1990-01-01",
            "gender": "Male",
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "WALK_IN",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("folder_number", response.data)

    def test_create_patient_as_admin(self):
        """Test that admin can create patients."""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse("patients:patient-list-create")
        data = {
            "first_name": "Test",
            "last_name": "Patient",
            "date_of_birth": "1990-01-01",
            "gender": "Male",
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "WALK_IN",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_referred_patient_with_referral(self):
        """Test creating a referred patient with referral details."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:patient-list-create")
        data = {
            "first_name": "Referred",
            "last_name": "Patient",
            "date_of_birth": "1990-01-01",
            "gender": "Male",
            "phone_number": "+233241234567",
            "is_child": False,
            "acquisition_channel_code": "REFERRED",
            "referral": {
                "referrer_name": "Dr. External",
            },
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNotNone(response.data.get("referral"))

    def test_search_patients(self):
        """Test searching patients by various fields."""
        # Create a patient first
        self.client.force_authenticate(user=self.secretary_user)
        Patient.objects.create(
            first_name="Unique",
            last_name="Testname",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )

        url = reverse("patients:patient-list-create")
        response = self.client.get(url, {"search": "Unique"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class PatientRetrieveUpdateDestroyViewTests(PatientViewTestMixin, APITestCase):
    """Tests for patient retrieve, update, and delete endpoints."""

    def setUp(self):
        """Create a patient for testing."""
        self.patient = Patient.objects.create(
            first_name="Test",
            last_name="Patient",
            date_of_birth=date(1990, 1, 1),
            gender=Gender.MALE,
            phone_number="+233241234567",
            is_child=False,
            acquisition_channel=self.walk_in_channel,
        )

    def test_retrieve_patient(self):
        """Test retrieving a patient."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:patient-detail", kwargs={"id": self.patient.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["folder_number"], self.patient.folder_number)

    def test_update_patient_requires_front_desk_role(self):
        """Test that only front desk staff can update patients."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:patient-detail", kwargs={"id": self.patient.id})
        response = self.client.patch(url, {"first_name": "Updated"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_patient_as_secretary(self):
        """Test that secretary can update patients."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:patient-detail", kwargs={"id": self.patient.id})
        response = self.client.patch(url, {"first_name": "Updated"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["full_name"], "Updated Patient")

    def test_delete_patient_requires_admin_role(self):
        """Test that only admin can delete patients."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:patient-detail", kwargs={"id": self.patient.id})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_patient_as_admin(self):
        """Test that admin can delete patients."""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse("patients:patient-detail", kwargs={"id": self.patient.id})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Patient.objects.filter(id=self.patient.id).exists())


class PatientTypeViewTests(PatientViewTestMixin, APITestCase):
    """Tests for patient type endpoints."""

    def test_list_patient_types(self):
        """Test listing patient types."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:patienttype-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_patient_type_requires_admin(self):
        """Test that only admin can create patient types."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:patienttype-list-create")
        response = self.client.post(url, {"name": "VIP"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_patient_type_as_admin(self):
        """Test that admin can create patient types."""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse("patients:patienttype-list-create")
        response = self.client.post(url, {"name": "VIP", "is_active": True}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class AcquisitionChannelViewTests(PatientViewTestMixin, APITestCase):
    """Tests for acquisition channel endpoints."""

    def test_list_acquisition_channels(self):
        """Test listing acquisition channels."""
        self.client.force_authenticate(user=self.dentist_user)
        url = reverse("patients:acquisitionchannel-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_channel_requires_admin(self):
        """Test that only admin can create acquisition channels."""
        self.client.force_authenticate(user=self.secretary_user)
        url = reverse("patients:acquisitionchannel-list-create")
        response = self.client.post(
            url,
            {"code": "NEW", "name": "New Channel"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
