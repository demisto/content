### this script populate content descriptor with correct dates and assetId


output=$(git diff --name-status $2 > changelog.txt)
echo "1 - $output"
output=$(git diff  --diff-filter=D $2 > delete-changelog.txt)
echo "2 - $output"

output=$(ls)
echo "3 - $output"
ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION changelog.txt delete-changelog.txt $ASSETID