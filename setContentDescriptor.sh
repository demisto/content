### this script populate content descriptor with correct dates and assetId

git diff --name-status $2 > changelog.txt
git diff  --diff-filter=D $2 > delete-changelog.txt

ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION changelog.txt delete-changelog.txt $ASSETID