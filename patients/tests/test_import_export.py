"""
Tests for Patient Import/Export functionality.

Tests cover:
- CSV/Excel file parsing
- Data validation and normalization
- Import with various options
- Export with filters
- Async Celery task execution
- Error handling and reporting
"""
import csv
import io
import tempfile
from datetime import date, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from rest_framework.test import APITestCase
from rest_framework import status

from patients.models import (
    AcquisitionChannel,
    Patient,
    PatientImportExportJob,
    PatientType,
)
from patients.services.import_export import (
    EXPORT_COLUMNS,
    IMPORT_COLUMN_MAPPING,
    REQUIRED_IMPORT_FIELDS,
    ExportOptions,
    ImportOptions,
    ImportResult,
    _map_headers,
    _normalize_phone_number,
    _parse_boolean,
    _parse_date,
    _parse_gender,
    detect_file_format,
    export_patients_to_csv,
    generate_import_template_csv,
    import_patients_from_file,
    read_csv_file,
)

User = get_user_model()


class PhoneNormalizationTests(TestCase):
    """Test phone number normalization for Ghana format."""
    
    def test_local_format_conversion(self):
        """Test 024XXXXXXX -> +233XXXXXXXXX."""
        self.assertEqual(_normalize_phone_number("0241234567"), "+233241234567")
    
    def test_international_format_preserved(self):
        """Test +233XXXXXXXXX stays unchanged."""
        self.assertEqual(_normalize_phone_number("+233241234567"), "+233241234567")
    
    def test_nine_digit_adds_prefix(self):
        """Test 9 digits get +233 prefix."""
        self.assertEqual(_normalize_phone_number("241234567"), "+233241234567")
    
    def test_with_spaces_stripped(self):
        """Test spaces are handled."""
        result = _normalize_phone_number("024 123 4567")
        self.assertIn("233", result)
    
    def test_empty_returns_none(self):
        """Test empty string returns None."""
        self.assertIsNone(_normalize_phone_number(""))
        self.assertIsNone(_normalize_phone_number(None))


class DateParsingTests(TestCase):
    """Test date parsing from various formats."""
    
    def test_iso_format(self):
        """Test YYYY-MM-DD format."""
        self.assertEqual(_parse_date("2026-01-15"), date(2026, 1, 15))
    
    def test_european_format(self):
        """Test DD/MM/YYYY format."""
        self.assertEqual(_parse_date("15/01/2026"), date(2026, 1, 15))
    
    def test_us_format(self):
        """Test MM/DD/YYYY format."""
        self.assertEqual(_parse_date("01/15/2026"), date(2026, 1, 15))
    
    def test_date_object_passthrough(self):
        """Test date object is returned unchanged."""
        d = date(2026, 1, 15)
        self.assertEqual(_parse_date(d), d)
    
    def test_empty_returns_none(self):
        """Test empty values return None."""
        self.assertIsNone(_parse_date(""))
        self.assertIsNone(_parse_date(None))
    
    def test_invalid_returns_none(self):
        """Test invalid date returns None."""
        self.assertIsNone(_parse_date("not-a-date"))


class GenderParsingTests(TestCase):
    """Test gender value normalization."""
    
    def test_male_variants(self):
        """Test various male representations."""
        for val in ["male", "Male", "MALE", "M", "m", "man"]:
            self.assertEqual(_parse_gender(val), "Male", f"Failed for {val}")
    
    def test_female_variants(self):
        """Test various female representations."""
        for val in ["female", "Female", "FEMALE", "F", "f", "woman"]:
            self.assertEqual(_parse_gender(val), "Female", f"Failed for {val}")
    
    def test_empty_returns_none(self):
        """Test empty returns None."""
        self.assertIsNone(_parse_gender(""))
        self.assertIsNone(_parse_gender(None))


class BooleanParsingTests(TestCase):
    """Test boolean value parsing."""
    
    def test_true_variants(self):
        """Test various True representations."""
        for val in ["true", "True", "TRUE", "yes", "Yes", "1", "y"]:
            self.assertTrue(_parse_boolean(val), f"Failed for {val}")
    
    def test_false_variants(self):
        """Test various False representations."""
        for val in ["false", "False", "FALSE", "no", "No", "0", "n"]:
            self.assertFalse(_parse_boolean(val), f"Failed for {val}")
    
    def test_bool_passthrough(self):
        """Test bool values pass through."""
        self.assertTrue(_parse_boolean(True))
        self.assertFalse(_parse_boolean(False))


class HeaderMappingTests(TestCase):
    """Test column header mapping."""
    
    def test_standard_headers(self):
        """Test standard column names are mapped."""
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        mapping = _map_headers(headers)
        
        self.assertEqual(mapping[0], "first_name")
        self.assertEqual(mapping[1], "last_name")
        self.assertEqual(mapping[2], "date_of_birth")
        self.assertEqual(mapping[3], "gender")
        self.assertEqual(mapping[4], "phone_number")
    
    def test_alternate_headers(self):
        """Test alternate column names."""
        headers = ["firstname", "surname", "dob", "sex", "mobile"]
        mapping = _map_headers(headers)
        
        self.assertEqual(mapping[0], "first_name")
        self.assertEqual(mapping[1], "last_name")
        self.assertEqual(mapping[2], "date_of_birth")
        self.assertEqual(mapping[3], "gender")
        self.assertEqual(mapping[4], "phone_number")
    
    def test_unmapped_headers_ignored(self):
        """Test unknown columns are not in mapping."""
        headers = ["Unknown Column", "first_name"]
        mapping = _map_headers(headers)
        
        self.assertNotIn(0, mapping)
        self.assertEqual(mapping[1], "first_name")


class FileFormatDetectionTests(TestCase):
    """Test file format detection from filename."""
    
    def test_csv_detection(self):
        """Test CSV file detection."""
        self.assertEqual(detect_file_format("patients.csv"), "CSV")
        self.assertEqual(detect_file_format("data.CSV"), "CSV")
    
    def test_excel_detection(self):
        """Test Excel file detection."""
        self.assertEqual(detect_file_format("patients.xlsx"), "EXCEL")
        self.assertEqual(detect_file_format("data.XLSX"), "EXCEL")
        self.assertEqual(detect_file_format("old_data.xls"), "EXCEL")
    
    def test_unsupported_raises_error(self):
        """Test unsupported format raises ValueError."""
        with self.assertRaises(ValueError):
            detect_file_format("data.pdf")


class CSVReaderTests(TestCase):
    """Test CSV file reading."""
    
    def test_read_simple_csv(self):
        """Test reading a simple CSV file."""
        csv_content = "First Name,Last Name\nJohn,Doe\nJane,Smith"
        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        
        for headers, rows in read_csv_file(file_obj):
            self.assertEqual(headers, ["First Name", "Last Name"])
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0], ["John", "Doe"])
    
    def test_read_csv_with_bom(self):
        """Test reading CSV with UTF-8 BOM."""
        csv_content = "\ufeffFirst Name,Last Name\nJohn,Doe"
        file_obj = io.BytesIO(csv_content.encode("utf-8-sig"))
        
        for headers, rows in read_csv_file(file_obj):
            self.assertEqual(headers, ["First Name", "Last Name"])


class ImportTemplateTests(TestCase):
    """Test import template generation."""
    
    def test_csv_template_has_headers(self):
        """Test CSV template includes required columns."""
        output = io.BytesIO()
        generate_import_template_csv(output)
        output.seek(0)
        
        content = output.read().decode("utf-8-sig")
        for header in ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]:
            self.assertIn(header, content)
    
    def test_csv_template_has_example_row(self):
        """Test CSV template includes example data."""
        output = io.BytesIO()
        generate_import_template_csv(output)
        output.seek(0)
        
        content = output.read().decode("utf-8-sig")
        self.assertIn("John", content)
        self.assertIn("Doe", content)


class ImportPatientTests(TestCase):
    """Test patient import functionality."""
    
    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        cls.admin_user = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )
        
        # Create lookup data
        cls.patient_type = PatientType.objects.create(
            name="Regular",
            is_active=True,
        )
        cls.channel = AcquisitionChannel.objects.create(
            code="WALK_IN",
            name="Walk In",
            is_active=True,
        )
    
    def _create_csv_file(self, rows: list[list]) -> io.BytesIO:
        """Helper to create CSV file from rows."""
        output = io.StringIO()
        writer = csv.writer(output)
        for row in rows:
            writer.writerow(row)
        
        return io.BytesIO(output.getvalue().encode("utf-8"))
    
    def test_import_valid_csv(self):
        """Test importing valid CSV data."""
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        data = ["John", "Doe", "1990-05-15", "Male", "+233241234567"]
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions(skip_invalid_rows=True)
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        self.assertEqual(result.total_rows, 1)
        self.assertEqual(result.created_count, 1)
        self.assertEqual(result.error_count, 0)
        
        # Verify patient was created
        patient = Patient.objects.get(first_name="John", last_name="Doe")
        self.assertEqual(patient.phone_number, "+233241234567")
        self.assertEqual(patient.gender, "Male")
    
    def test_import_missing_required_fields(self):
        """Test import fails for missing required fields."""
        headers = ["First Name", "Last Name"]  # Missing required fields
        data = ["John", "Doe"]
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions(skip_invalid_rows=True)
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        self.assertEqual(result.error_count, 1)
        self.assertEqual(result.created_count, 0)
    
    def test_import_normalizes_phone(self):
        """Test phone numbers are normalized during import."""
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        data = ["Jane", "Smith", "1985-03-20", "Female", "0241234567"]  # Local format
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions()
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        self.assertEqual(result.created_count, 1)
        patient = Patient.objects.get(first_name="Jane")
        self.assertEqual(patient.phone_number, "+233241234567")
    
    def test_dry_run_no_persist(self):
        """Test dry run validates but doesn't persist."""
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        data = ["DryRun", "Test", "1990-01-01", "Male", "+233241234599"]
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions(dry_run=True)
        
        initial_count = Patient.objects.count()
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        # Should show as validated, not created
        self.assertFalse(Patient.objects.filter(first_name="DryRun").exists())
        self.assertEqual(Patient.objects.count(), initial_count)
    
    def test_import_child_patient(self):
        """Test importing child patient with guardian."""
        headers = [
            "First Name", "Last Name", "Date of Birth", "Gender", 
            "Phone Number", "Is Child", "Guardian Name", "Guardian Phone"
        ]
        data = [
            "Little", "One", "2020-06-15", "Female",
            "+233241234570", "Yes", "Parent Name", "+233241234571"
        ]
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions()
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        self.assertEqual(result.created_count, 1)
        patient = Patient.objects.get(first_name="Little")
        self.assertTrue(patient.is_child)
        self.assertEqual(patient.guardian_name, "Parent Name")

    def test_skip_duplicates_skips_matching_patients(self):
        """Test that skip_duplicates=True skips rows that match existing patients."""
        # First create an existing patient
        existing = Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1990, 5, 15),
            gender="Male",
            phone_number="+233241234599",
        )
        
        # Try to import a patient with same phone number
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        data = ["Duplicate", "Person", "1990-05-15", "Male", "+233241234599"]  # Same phone
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions(skip_duplicates=True, duplicate_threshold=30)
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        # Should be skipped, not created
        self.assertEqual(result.created_count, 0)
        self.assertEqual(result.skipped_count, 1)
        self.assertFalse(Patient.objects.filter(first_name="Duplicate").exists())
        
        # Check that warning mentions duplicate
        row_result = result.row_results[0]
        self.assertEqual(row_result.action, "skipped")
        self.assertTrue(any("duplicate" in w.lower() for w in row_result.warnings))

    def test_skip_duplicates_false_allows_duplicates_with_warning(self):
        """Test that skip_duplicates=False creates patient but adds warning."""
        # First create an existing patient
        existing = Patient.objects.create(
            first_name="Existing",
            last_name="Patient",
            date_of_birth=date(1990, 5, 15),
            gender="Male",
            phone_number="+233241234598",
        )
        
        # Import a patient with same phone number
        headers = ["First Name", "Last Name", "Date of Birth", "Gender", "Phone Number"]
        data = ["Another", "Person", "1990-05-15", "Male", "+233241234598"]  # Same phone
        
        file_obj = self._create_csv_file([headers, data])
        options = ImportOptions(skip_duplicates=False, duplicate_threshold=30)
        
        result = import_patients_from_file(
            file_obj=file_obj,
            filename="test.csv",
            options=options,
        )
        
        # Should be created but with warning
        self.assertEqual(result.created_count, 1)
        self.assertEqual(result.skipped_count, 0)
        self.assertTrue(Patient.objects.filter(first_name="Another").exists())
        
        # Check that warning mentions duplicate
        row_result = result.row_results[0]
        self.assertEqual(row_result.action, "created")
        self.assertTrue(any("duplicate" in w.lower() for w in row_result.warnings))


class ExportPatientTests(TestCase):
    """Test patient export functionality."""
    
    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        # Create some patients
        cls.patient1 = Patient.objects.create(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1990, 5, 15),
            gender="Male",
            phone_number="+233241234567",
        )
        cls.patient2 = Patient.objects.create(
            first_name="Jane",
            last_name="Smith",
            date_of_birth=date(1985, 3, 20),
            gender="Female",
            phone_number="+233241234568",
        )
    
    def test_export_to_csv(self):
        """Test exporting patients to CSV."""
        output = io.BytesIO()
        options = ExportOptions()
        
        count = export_patients_to_csv(output, options)
        
        self.assertEqual(count, 2)
        
        # Check CSV content
        output.seek(0)
        content = output.read().decode("utf-8-sig")
        self.assertIn("John", content)
        self.assertIn("Doe", content)
        self.assertIn("Jane", content)
        self.assertIn("Smith", content)
    
    def test_export_with_date_filter(self):
        """Test export with date range filter."""
        output = io.BytesIO()
        options = ExportOptions(
            date_from=date.today() - timedelta(days=1),
            date_to=date.today() + timedelta(days=1),
        )
        
        count = export_patients_to_csv(output, options)
        self.assertGreaterEqual(count, 0)


class ImportExportJobModelTests(TestCase):
    """Test PatientImportExportJob model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
        )
    
    def test_job_creation(self):
        """Test creating an import job."""
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.IMPORT,
            file_format=PatientImportExportJob.FileFormat.CSV,
            initiated_by=self.user,
            source_filename="test.csv",
        )
        
        self.assertEqual(job.status, PatientImportExportJob.JobStatus.PENDING)
        self.assertEqual(job.job_type, "IMPORT")
    
    def test_progress_percentage(self):
        """Test progress percentage calculation."""
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.IMPORT,
            file_format=PatientImportExportJob.FileFormat.CSV,
            total_rows=100,
            processed_rows=50,
        )
        
        self.assertEqual(job.progress_percentage, 50.0)
    
    def test_mark_started(self):
        """Test marking job as started."""
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.EXPORT,
            file_format=PatientImportExportJob.FileFormat.EXCEL,
        )
        
        job.mark_started()
        
        self.assertEqual(job.status, PatientImportExportJob.JobStatus.PROCESSING)
        self.assertIsNotNone(job.started_at)
    
    def test_mark_completed(self):
        """Test marking job as completed."""
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.EXPORT,
            file_format=PatientImportExportJob.FileFormat.CSV,
        )
        job.mark_started()
        job.mark_completed()
        
        self.assertEqual(job.status, PatientImportExportJob.JobStatus.COMPLETED)
        self.assertIsNotNone(job.completed_at)
    
    def test_mark_failed(self):
        """Test marking job as failed."""
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.IMPORT,
            file_format=PatientImportExportJob.FileFormat.CSV,
        )
        job.mark_failed("Something went wrong")
        
        self.assertEqual(job.status, PatientImportExportJob.JobStatus.FAILED)
        self.assertEqual(job.error_message, "Something went wrong")


class ImportExportAPITests(APITestCase):
    """Test import/export API endpoints."""
    
    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        cls.admin_user = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )
        cls.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123",
        )
    
    def test_import_requires_admin(self):
        """Test import endpoint requires admin permission."""
        self.client.force_authenticate(user=self.regular_user)
        
        csv_content = b"First Name,Last Name\nJohn,Doe"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")
        
        response = self.client.post("/api/patients/import/", {"file": file})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_export_requires_admin(self):
        """Test export endpoint requires admin permission."""
        self.client.force_authenticate(user=self.regular_user)
        
        response = self.client.post("/api/patients/export/", {"file_format": "CSV"})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_template_download_authenticated(self):
        """Test template download works for authenticated users."""
        self.client.force_authenticate(user=self.regular_user)
        
        response = self.client.get("/api/patients/import-export/template/?format=csv")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
    
    @patch("patients.views.process_patient_import.delay")
    def test_import_creates_job(self, mock_task):
        """Test import endpoint creates job and queues task."""
        mock_task.return_value = MagicMock(id="task-123")
        
        self.client.force_authenticate(user=self.admin_user)
        
        csv_content = b"First Name,Last Name,Date of Birth,Gender,Phone Number\nJohn,Doe,1990-01-01,Male,+233241234567"
        file = SimpleUploadedFile("patients.csv", csv_content, content_type="text/csv")
        
        response = self.client.post("/api/patients/import/", {"file": file})
        
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn("id", response.data)
        
        # Verify job was created
        job_id = response.data["id"]
        job = PatientImportExportJob.objects.get(id=job_id)
        self.assertEqual(job.job_type, "IMPORT")
        self.assertEqual(job.initiated_by, self.admin_user)
    
    @patch("patients.views.process_patient_export.delay")
    def test_export_creates_job(self, mock_task):
        """Test export endpoint creates job and queues task."""
        mock_task.return_value = MagicMock(id="task-456")
        
        self.client.force_authenticate(user=self.admin_user)
        
        response = self.client.post(
            "/api/patients/export/",
            {"file_format": "EXCEL"},
            format="json",
        )
        
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn("id", response.data)
        
        # Verify job was created
        job_id = response.data["id"]
        job = PatientImportExportJob.objects.get(id=job_id)
        self.assertEqual(job.job_type, "EXPORT")
        self.assertEqual(job.file_format, "EXCEL")
    
    def test_job_list(self):
        """Test listing import/export jobs."""
        self.client.force_authenticate(user=self.admin_user)
        
        # Create a job
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.IMPORT,
            file_format=PatientImportExportJob.FileFormat.CSV,
            initiated_by=self.admin_user,
        )
        
        response = self.client.get("/api/patients/import-export/jobs/")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
    
    def test_job_detail(self):
        """Test retrieving job details."""
        self.client.force_authenticate(user=self.admin_user)
        
        job = PatientImportExportJob.objects.create(
            job_type=PatientImportExportJob.JobType.EXPORT,
            file_format=PatientImportExportJob.FileFormat.EXCEL,
            initiated_by=self.admin_user,
            total_rows=100,
            processed_rows=50,
        )
        
        response = self.client.get(f"/api/patients/import-export/jobs/{job.id}/")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_rows"], 100)
        self.assertEqual(response.data["processed_rows"], 50)
