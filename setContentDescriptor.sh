### this script populate content descriptor with correct dates and assetId

git diff --name-status $2 > changelog.txt

ASSETID=$1
VERSION=$3

./release_notes/release_notes  $VERSION changelog.txt $ASSETID