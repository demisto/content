#!/bin/bash
# Create zip package in pack folder

PACK_NAME="SupernaZeroTrust"
PACK_DIR="/Users/andrew/Documents/integrations/XSOAR/content/Packs/$PACK_NAME"

cd /Users/andrew/Documents/integrations/XSOAR/content

# Get current version from pack_metadata.json
VERSION=$(grep '"currentVersion"' "$PACK_DIR/pack_metadata.json" | cut -d'"' -f4)

echo "Creating zip for $PACK_NAME version $VERSION..."

# Create zip
demisto-sdk zip-packs -i "Packs/$PACK_NAME" -o "$PACK_DIR"

# Move and rename zip
if [ -f "$PACK_DIR/uploadable_packs/$PACK_NAME.zip" ]; then
    mv "$PACK_DIR/uploadable_packs/$PACK_NAME.zip" "$PACK_DIR/$PACK_NAME-$VERSION.zip"
    rm -rf "$PACK_DIR/uploadable_packs"
    echo ""
    echo "✅ Zip created: $PACK_DIR/$PACK_NAME-$VERSION.zip"
    ls -lh "$PACK_DIR/$PACK_NAME-$VERSION.zip"
else
    echo "❌ Zip creation failed"
fi
