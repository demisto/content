#!/bin/bash
#
# Official XSOAR 8.x Cloud Upload Script
# Based on: https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/upload/README.md
#

echo "=========================================="
echo "XSOAR 8.x Cloud Upload Script"
echo "=========================================="
echo ""

# XSOAR 8.x Cloud Configuration
# For XSOAR 8.x cloud, we must use XSIAM authentication mode
export DEMISTO_BASE_URL="https://api-superna.crtx.ca.paloaltonetworks.com"
export DEMISTO_API_KEY="j6vfrufSiHIYT3T4IlGXy0b9YtLYSlJY39rQjde1I3uMmju3ek4qkh8xC4UXImIopCAPR8z7YY5FFzTSB5Bya5VKvYCkyuazIl0kPGmdWnJlUVToBi0HxrLOObsWazsj"
export XSIAM_AUTH_ID="3"

echo "Configuration:"
echo "  Base URL: ${DEMISTO_BASE_URL}"
echo "  Auth ID: ${XSIAM_AUTH_ID}"
echo "  API Key: ${DEMISTO_API_KEY:0:20}..."
echo ""

# Navigate to content directory
cd /Users/andrew/Documents/integrations/XSOAR/content

echo "[1/2] Validating pack..."
demisto-sdk validate -i Packs/SupernaZeroTrust

echo ""
echo "[2/2] Uploading pack to XSOAR 8.x cloud..."
echo ""

# Official command for XSOAR 8.x cloud (requires -z flag, XSIAM_AUTH_ID env var)
demisto-sdk upload \
  -i Packs/SupernaZeroTrust \
  -z \
  --insecure \
  --skip_validation \
  --console-log-threshold DEBUG

echo ""
echo "=========================================="
echo "Upload Complete!"
echo "=========================================="
