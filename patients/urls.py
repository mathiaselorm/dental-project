"""
Patient Management URL Configuration.

All endpoints require authentication.
"""
from django.urls import path

from .views import (
    AcquisitionChannelListCreateView,
    AcquisitionChannelRetrieveUpdateDestroyView,
    AllMergeHistoryView,
    AllPatientsListView,
    DuplicateCheckView,
    DuplicateScanView,
    ImportExportJobCancelView,
    ImportExportJobDetailView,
    ImportExportJobDownloadView,
    ImportExportJobListView,
    ImportTemplateDownloadView,
    PatientDuplicatesView,
    PatientExportView,
    PatientImportView,
    PatientListCreateView,
    PatientMergeHistoryView,
    PatientMergeView,
    PatientQuickExportView,
    PatientRestoreView,
    PatientRetrieveUpdateDestroyView,
    PatientTypeListCreateView,
    PatientTypeRetrieveUpdateDestroyView,
)


app_name = "patients"

urlpatterns = [
    # Patient CRUD
    path("", PatientListCreateView.as_view(), name="patient-list-create"),
    path("<uuid:id>/", PatientRetrieveUpdateDestroyView.as_view(), name="patient-detail"),
    
    # Admin: All patients (including deleted) and restore
    path("all/", AllPatientsListView.as_view(), name="patient-list-all"),
    path("<uuid:id>/restore/", PatientRestoreView.as_view(), name="patient-restore"),

    # Duplicate Detection
    path("duplicates/check/", DuplicateCheckView.as_view(), name="duplicate-check"),
    path("duplicates/scan/", DuplicateScanView.as_view(), name="duplicate-scan"),
    path("<uuid:id>/duplicates/", PatientDuplicatesView.as_view(), name="patient-duplicates"),

    # Patient Merge
    path("merge/", PatientMergeView.as_view(), name="patient-merge"),
    path("merge/history/", AllMergeHistoryView.as_view(), name="merge-history-all"),
    path("<uuid:id>/merge-history/", PatientMergeHistoryView.as_view(), name="patient-merge-history"),

    # Import/Export
    path("import/", PatientImportView.as_view(), name="patient-import"),
    path("export/", PatientExportView.as_view(), name="patient-export"),
    path("export/quick/", PatientQuickExportView.as_view(), name="patient-export-quick"),
    path("import-export/template/", ImportTemplateDownloadView.as_view(), name="import-template"),
    path("import-export/jobs/", ImportExportJobListView.as_view(), name="import-export-jobs"),
    path("import-export/jobs/<uuid:job_id>/", ImportExportJobDetailView.as_view(), name="import-export-job-detail"),
    path("import-export/jobs/<uuid:job_id>/download/", ImportExportJobDownloadView.as_view(), name="import-export-job-download"),
    path("import-export/jobs/<uuid:job_id>/cancel/", ImportExportJobCancelView.as_view(), name="import-export-job-cancel"),

    # Patient Types (lookup table)
    path("types/", PatientTypeListCreateView.as_view(), name="patienttype-list-create"),
    path("types/<uuid:id>/", PatientTypeRetrieveUpdateDestroyView.as_view(), name="patienttype-detail"),

    # Acquisition Channels (lookup table)
    path("channels/", AcquisitionChannelListCreateView.as_view(), name="acquisitionchannel-list-create"),
    path("channels/<uuid:id>/", AcquisitionChannelRetrieveUpdateDestroyView.as_view(), name="acquisitionchannel-detail"),
]
