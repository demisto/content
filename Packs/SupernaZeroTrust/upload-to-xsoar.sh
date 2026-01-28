#!/bin/bash
#
# Upload SupernaZeroTrust Pack to XSOAR Instance
#
# Usage: ./upload-to-xsoar.sh <AUTH_ID>
# Example: ./upload-to-xsoar.sh 1234567890
#

# Check if Auth ID is provided
if [ -z "$1" ]; then
    echo "ERROR: Auth ID is required"
    echo ""
    echo "Usage: ./upload-to-xsoar.sh <AUTH_ID>"
    echo ""
    echo "To get your Auth ID:"
    echo "1. Log into XSOAR: https://superna.crtx.ca.paloaltonetworks.com"
    echo "2. Go to: Settings → Configurations → API Keys"
    echo "3. Find your API key and copy the Auth ID"
    echo ""
    exit 1
fi

AUTH_ID="$1"

# Set environment variables
export DEMISTO_BASE_URL=https://api-superna.crtx.ca.paloaltonetworks.com
export DEMISTO_API_KEY=j6vfrufSiHIYT3T4IlGXy0b9YtLYSlJY39rQjde1I3uMmju3ek4qkh8xC4UXImIopCAPR8z7YY5FFzTSB5Bya5VKvYCkyuazIl0kPGmdWnJlUVToBi0HxrLOObsWazsj
export XSIAM_AUTH_ID="$AUTH_ID"

echo "=========================================="
echo "Uploading SupernaZeroTrust Pack to XSOAR"
echo "=========================================="
echo ""
echo "API URL: $DEMISTO_BASE_URL"
echo "Auth ID: $AUTH_ID"
echo ""

# Change to content directory
cd /Users/andrew/Documents/integrations/XSOAR/content

# Upload the pack
echo "Starting upload..."
demisto-sdk upload -i Packs/SupernaZeroTrust -z --insecure --skip_validation --override-existing

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "✅ SUCCESS! Pack uploaded successfully"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo "1. Open XSOAR: https://superna.crtx.ca.paloaltonetworks.com"
    echo "2. Go to: Settings → Integrations → Servers & Services"
    echo "3. Search for: Superna Zero Trust"
    echo "4. Click 'Add instance' to configure"
    echo "5. Enter your API URL and API Key"
    echo "6. Click 'Test' to verify connection"
    echo ""
else
    echo ""
    echo "=========================================="
    echo "❌ ERROR: Upload failed"
    echo "=========================================="
    echo ""
    echo "Troubleshooting:"
    echo "- Verify your Auth ID is correct"
    echo "- Check your API key has 'Instance Administrator' role"
    echo "- Ensure you have network access to the XSOAR instance"
    echo ""
fi
