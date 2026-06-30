#!/bin/bash
# Wrapper script to run ClamAV scanning from ModSecurity SecRule FILES_TMPNAMES
# Exits with 0 if clean, or non-zero (1) if malware was detected.

FILE_PATH="$1"

if [ -z "$FILE_PATH" ]; then
    echo "No file path specified"
    exit 0
fi

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "File not found: $FILE_PATH"
    exit 0
fi

# Use clamdscan if daemon is running (high performance), fallback to clamscan
if command -v clamdscan >/dev/null 2>&1; then
    clamdscan --quiet --no-summary "$FILE_PATH"
    EXIT_CODE=$?
else
    if command -v clamscan >/dev/null 2>&1; then
        clamscan --quiet --no-summary "$FILE_PATH"
        EXIT_CODE=$?
    else
        echo "ClamAV scanner (clamdscan/clamscan) not installed on this system."
        exit 0 # Safe fallback (fail-open)
    fi
fi

# ClamAV exit codes: 
# 0 = Clean
# 1 = Virus/Malware found
# 2 = Error occurred
if [ $EXIT_CODE -eq 1 ]; then
    echo "MALWARE DETECTED in file: $FILE_PATH"
    exit 1
elif [ $EXIT_CODE -eq 2 ]; then
    echo "ClamAV scan error for file: $FILE_PATH"
    exit 0 # Safe fallback
fi

exit 0
