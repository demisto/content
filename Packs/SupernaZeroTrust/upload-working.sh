#!/bin/bash
#
# WORKING XSOAR 8.x Upload Script
# Uses Standard API Key (ID: 3) with Instance Administrator role
#

echo "=========================================="
echo "XSOAR 8.x Pack Upload - WORKING VERSION"
echo "=========================================="
echo ""

# CRITICAL: Must use Standard security level API key with Instance Administrator role
export DEMISTO_BASE_URL="https://api-superna.crtx.ca.paloaltonetworks.com"
export DEMISTO_API_KEY="j6vfrufSiHIYT3T4IlGXy0b9YtLYSlJY39rQjde1I3uMmju3ek4qkh8xC4UXImIopCAPR8z7YY5FFzTSB5Bya5VKvYCkyuazIl0kPGmdWnJlUVToBi0HxrLOObsWazsj"
export XSIAM_AUTH_ID="3"

echo "Configuration:"
echo "  Base URL: ${DEMISTO_BASE_URL}"
echo "  Auth ID: ${XSIAM_AUTH_ID}"
echo "  API Key: Standard (Instance Administrator)"
echo ""

# Navigate to content directory
cd /Users/andrew/Documents/integrations/XSOAR/content

echo "Uploading pack to XSOAR 8.x cloud..."
echo ""

demisto-sdk upload \
  -i Packs/SupernaZeroTrust \
  -z \
  --insecure \
  --skip_validation \
  --console-log-threshold INFO

echo ""
echo "=========================================="
echo "Upload Complete!"
echo "=========================================="
echo ""
echo "To find your pack in XSOAR:"
echo "1. Settings → About → Installed Content Packs"
echo "2. Settings → Integrations → Servers & Services (search 'SupernaZeroTrust')"
echo "3. Playbooks menu (search 'Superna')"
