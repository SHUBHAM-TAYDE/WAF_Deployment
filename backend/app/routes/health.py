import os
from fastapi import APIRouter, HTTPException
from app.config.settings import settings
from app.models.response_models import HealthResponse
from app.services.log_reader import get_parsed_files_count, get_all_logs
from app.services.settings_manager import settings_manager
from app.services.anti_defacement import anti_defacement_service

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Get API health status and log directory info.
    """
    log_dir_exists = os.path.exists(settings.LOG_DIR) and os.path.isdir(
        settings.LOG_DIR
    )
    parsed_files = get_parsed_files_count()

    return HealthResponse(
        status="ok",
        log_directory_exists=log_dir_exists,
        total_parsed_files=parsed_files,
    )


@router.post("/health/test-defacement")
async def test_defacement():
    """
    Simulates a defacement attack by creating a test file, modifying it,
    verifying WAF auto-restoration, and asserting that a WAF log alert is generated.
    """
    test_file = os.path.abspath(
        "/opt/ModSecurity/WAF_GUI/backend/scratch/defacement_test.html"
    )

    # 1. Create clean HTML page
    os.makedirs(os.path.dirname(test_file), exist_ok=True)
    clean_html = """<!DOCTYPE html>
<html>
<head><title>Clean Protected Page</title></head>
<body><h1>This is a clean, untouched, protected web page.</h1></body>
</html>
"""
    try:
        with open(test_file, "w") as f:
            f.write(clean_html)

        # 2. Configure WAF settings to monitor our test file
        settings_data = settings_manager.get_anti_defacement()
        original_enabled = settings_data.get("enabled", True)
        original_files = settings_data.get("monitored_files", [])
        original_interval = settings_data.get("check_interval_seconds", 5)

        settings_data["enabled"] = True
        settings_data["monitored_files"] = [test_file]
        settings_data["check_interval_seconds"] = 1
        settings_manager.update_anti_defacement(settings_data)

        # Allow service to prefetch and hash the file
        anti_defacement_service.load_monitored_files()

        # 3. Simulate defacement modification
        defaced_payload = "<html><body><h1>DEFACED BY HACKER!!!</h1></body></html>"
        with open(test_file, "w") as f:
            f.write(defaced_payload)

        # 4. Trigger integrity check manually to restore the file and write logs
        await anti_defacement_service.check_integrity()

        # 5. Read restored file to check integrity
        with open(test_file, "r") as f:
            restored = f.read()

        restored_ok = restored == clean_html

        # 6. Verify WAF Log Alert generation
        logs = get_all_logs()
        defacement_logs = [
            log_entry
            for log_entry in logs
            if log_entry.attack_type == "Web Anti-Defacement" and log_entry.uri == test_file
        ]
        alert_ok = len(defacement_logs) > 0

    finally:
        # Restore original configurations
        settings_data["enabled"] = original_enabled
        settings_data["monitored_files"] = original_files
        settings_data["check_interval_seconds"] = original_interval
        settings_manager.update_anti_defacement(settings_data)

        # Clean up disk
        if os.path.exists(test_file):
            os.remove(test_file)

    if not restored_ok:
        raise HTTPException(
            status_code=500, detail="File restoration failed. Content was not restored."
        )

    if not alert_ok:
        raise HTTPException(
            status_code=500,
            detail="Alert generation failed. No security log entry was found.",
        )

    return {
        "status": "success",
        "message": "Web Anti-Defacement test completed successfully! The defaced file was automatically restored and the Critical log alert was generated.",
    }


@router.get("/health/debug-defacement")
async def debug_defacement():
    """Returns the current runtime cache state of the Anti-Defacement service."""
    from app.services.anti_defacement import anti_defacement_service

    test_file = os.path.abspath(
        "/opt/ModSecurity/WAF_GUI/backend/scratch/defacement_test.html"
    )
    return {
        "settings": settings_manager.get_anti_defacement(),
        "cached_hashes": anti_defacement_service.cached_hashes,
        "cached_keys": list(anti_defacement_service.cached_contents.keys()),
        "test_file_exists": os.path.exists(test_file),
        "test_file_path": test_file,
    }
