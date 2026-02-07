"""
Celery tasks for async patient import/export operations.

Tasks:
- process_patient_import: Async bulk import from CSV/Excel
- process_patient_export: Async bulk export to CSV/Excel
"""
from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime
from typing import Optional

from celery import shared_task
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone

logger = logging.getLogger(__name__)


def _get_media_path(subdir: str, filename: str) -> str:
    """Generate a media storage path for import/export files."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name, ext = os.path.splitext(filename)
    return f"patient_import_export/{subdir}/{base_name}_{timestamp}{ext}"


@shared_task(
    bind=True,
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    time_limit=3600,  # 1 hour max
    soft_time_limit=3300,  # 55 minutes soft limit
)
def process_patient_import(
    self,
    job_id: str,
    source_file_path: str,
    original_filename: str,
    options_dict: dict,
) -> dict:
    """
    Async task to process patient import from CSV/Excel file.
    
    Args:
        job_id: UUID of the PatientImportExportJob record
        source_file_path: Path to the uploaded file
        original_filename: Original filename for format detection
        options_dict: Import options as dict
        
    Returns:
        Dict with import results summary
    """
    from patients.models import PatientImportExportJob
    from patients.services.import_export import (
        ImportOptions,
        ImportResult,
        import_patients_from_file,
        generate_import_error_report,
    )
    
    # Get job record
    try:
        job = PatientImportExportJob.objects.get(id=job_id)
    except PatientImportExportJob.DoesNotExist:
        logger.error(f"Import job {job_id} not found")
        return {"error": f"Job {job_id} not found"}
    
    # Update job with task ID
    job.celery_task_id = self.request.id
    job.mark_started()
    
    result = ImportResult()
    
    try:
        # Parse options
        options = ImportOptions(
            skip_duplicates=options_dict.get("skip_duplicates", False),
            update_existing=options_dict.get("update_existing", False),
            duplicate_threshold=options_dict.get("duplicate_threshold", 50),
            skip_invalid_rows=options_dict.get("skip_invalid_rows", True),
            dry_run=options_dict.get("dry_run", False),
            batch_size=options_dict.get("batch_size", 100),
        )
        
        # Open and process file
        # Check if it's a storage path or absolute path
        if default_storage.exists(source_file_path):
            file_obj = default_storage.open(source_file_path, "rb")
        else:
            file_obj = open(source_file_path, "rb")
        
        try:
            result = import_patients_from_file(
                file_obj=file_obj,
                filename=original_filename,
                options=options,
                job=job,
                request=None,  # No request in async context
                progress_callback=None,
            )
        finally:
            file_obj.close()
        
        # Update job with results
        job.processed_rows = result.processed_rows
        job.success_count = result.created_count + result.updated_count
        job.error_count = result.error_count
        job.skip_count = result.skipped_count
        job.row_errors = [
            {"row": r.row_number, "errors": r.errors}
            for r in result.row_results if r.errors
        ]
        
        # Generate error report if there are errors
        if result.error_count > 0:
            error_report_filename = f"import_errors_{job_id}.xlsx"
            error_report_path = _get_media_path("error_reports", error_report_filename)
            
            # Create temp file and write error report
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
            tmp_file_path = tmp_file.name
            try:
                generate_import_error_report(
                    result=result,
                    output_file=tmp_file,
                    file_format="EXCEL",
                )
                tmp_file.close()
                
                # Save to storage
                with open(tmp_file_path, "rb") as f:
                    default_storage.save(error_report_path, ContentFile(f.read()))
            finally:
                if os.path.exists(tmp_file_path):
                    os.unlink(tmp_file_path)
            
            job.result_file = error_report_path
        
        job.mark_completed()
        
        logger.info(
            f"Import job {job_id} completed: "
            f"{result.created_count} created, {result.updated_count} updated, "
            f"{result.error_count} errors, {result.skipped_count} skipped"
        )
        
        return {
            "job_id": str(job_id),
            "status": "completed",
            "total_rows": result.total_rows,
            "processed_rows": result.processed_rows,
            "created_count": result.created_count,
            "updated_count": result.updated_count,
            "error_count": result.error_count,
            "skip_count": result.skipped_count,
        }
        
    except Exception as e:
        logger.exception(f"Import job {job_id} failed: {e}")
        job.mark_failed(str(e))
        
        return {
            "job_id": str(job_id),
            "status": "failed",
            "error": str(e),
        }


@shared_task(
    bind=True,
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    time_limit=3600,  # 1 hour max
    soft_time_limit=3300,  # 55 minutes soft limit
)
def process_patient_export(
    self,
    job_id: str,
    file_format: str,
    options_dict: dict,
) -> dict:
    """
    Async task to export patients to CSV/Excel file.
    
    Args:
        job_id: UUID of the PatientImportExportJob record
        file_format: "CSV" or "EXCEL"
        options_dict: Export options as dict
        
    Returns:
        Dict with export results summary
    """
    from datetime import date
    from uuid import UUID
    
    from patients.models import PatientImportExportJob
    from patients.services.import_export import (
        ExportOptions,
        export_patients,
    )
    
    # Get job record
    try:
        job = PatientImportExportJob.objects.get(id=job_id)
    except PatientImportExportJob.DoesNotExist:
        logger.error(f"Export job {job_id} not found")
        return {"error": f"Job {job_id} not found"}
    
    # Update job with task ID
    job.celery_task_id = self.request.id
    job.mark_started()
    
    try:
        # Parse options
        date_from = None
        date_to = None
        
        if options_dict.get("date_from"):
            date_from = date.fromisoformat(options_dict["date_from"])
        if options_dict.get("date_to"):
            date_to = date.fromisoformat(options_dict["date_to"])
        
        patient_type_ids = [
            UUID(pid) for pid in options_dict.get("patient_type_ids", [])
        ]
        acquisition_channel_ids = [
            UUID(cid) for cid in options_dict.get("acquisition_channel_ids", [])
        ]
        
        options = ExportOptions(
            include_deleted=options_dict.get("include_deleted", False),
            date_from=date_from,
            date_to=date_to,
            patient_type_ids=patient_type_ids,
            acquisition_channel_ids=acquisition_channel_ids,
            search_query=options_dict.get("search_query"),
        )
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = ".csv" if file_format == "CSV" else ".xlsx"
        filename = f"patients_export_{timestamp}{ext}"
        export_path = _get_media_path("exports", filename)
        
        # Create export file
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
        tmp_file_path = tmp_file.name
        try:
            count = export_patients(
                output_file=tmp_file,
                file_format=file_format,
                options=options,
                job=job,
                request=None,  # No request in async context
            )
            tmp_file.close()
            
            # Save to storage
            with open(tmp_file_path, "rb") as f:
                default_storage.save(export_path, ContentFile(f.read()))
        finally:
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
        
        # Update job
        job.result_file = export_path
        job.success_count = count
        job.total_rows = count
        job.processed_rows = count
        job.mark_completed()
        
        logger.info(f"Export job {job_id} completed: {count} patients exported")
        
        return {
            "job_id": str(job_id),
            "status": "completed",
            "count": count,
            "file_path": export_path,
        }
        
    except Exception as e:
        logger.exception(f"Export job {job_id} failed: {e}")
        job.mark_failed(str(e))
        
        return {
            "job_id": str(job_id),
            "status": "failed",
            "error": str(e),
        }


@shared_task(bind=True)
def cleanup_old_import_export_files(self, days_old: int = 7) -> dict:
    """
    Cleanup task to remove old import/export files.
    
    Args:
        days_old: Delete files older than this many days
        
    Returns:
        Dict with cleanup statistics
    """
    from datetime import timedelta
    from patients.models import PatientImportExportJob
    
    cutoff_date = timezone.now() - timedelta(days=days_old)
    
    old_jobs = PatientImportExportJob.objects.filter(
        created_at__lt=cutoff_date,
        status__in=[
            PatientImportExportJob.JobStatus.COMPLETED,
            PatientImportExportJob.JobStatus.FAILED,
        ],
    )
    
    files_deleted = 0
    jobs_cleaned = 0
    
    for job in old_jobs:
        # Delete source file
        if job.source_file:
            try:
                if default_storage.exists(job.source_file):
                    default_storage.delete(job.source_file)
                    files_deleted += 1
            except Exception as e:
                logger.warning(f"Failed to delete source file {job.source_file}: {e}")
        
        # Delete result file
        if job.result_file:
            try:
                if default_storage.exists(job.result_file):
                    default_storage.delete(job.result_file)
                    files_deleted += 1
            except Exception as e:
                logger.warning(f"Failed to delete result file {job.result_file}: {e}")
        
        # Clear file references (but keep job for audit)
        job.source_file = None
        job.result_file = None
        job.save(update_fields=["source_file", "result_file", "updated_at"])
        jobs_cleaned += 1
    
    logger.info(f"Cleanup completed: {files_deleted} files deleted, {jobs_cleaned} jobs cleaned")
    
    return {
        "files_deleted": files_deleted,
        "jobs_cleaned": jobs_cleaned,
        "cutoff_date": cutoff_date.isoformat(),
    }
