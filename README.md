# Nessus_Scan_Onboarder
Interactive CLI to bulk-create authenticated or unauthenticated scans.

Nessus Interactive Scan Onboarder  v3.0

-----------------------------------------

Authenticated scans use pre-configured Nessus policies (with SSH key baked in).
The script reads the 'username' column from the CSV and maps it to the matching
policy fetched live from Nessus.

Requirements:
    pip install requests pandas openpyxl urllib3
