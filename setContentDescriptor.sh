### this script populate content descriptor with correct dates and assetId

echo "got 2 - $2"

echo "before 1"
git diff --name-status $2 > changelog.txt

echo "before 2"
git diff  --diff-filter=D $2 > delete-changelog.txt
echo "after 2"
ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION changelog.txt delete-changelog.txt $ASSETID