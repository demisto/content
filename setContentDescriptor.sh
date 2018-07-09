### this script populate content descriptor with correct dates and assetId

git diff --name-status $2 > changelog.txt
git diff  --diff-filter=D $2 > delete-changelog.txt
if [ ! -f changelog.txt ] || [ ! -f delete-changelog.txt ]
then
    echo "Change log files are not exist"
    exit 1
fi

ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION changelog.txt delete-changelog.txt $ASSETID