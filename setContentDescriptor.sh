### this script populate content descriptor with correct dates and assetId

git diff --name-status $2 &> changelog.txt
git diff  --diff-filter=D $2 &> delete-changelog.txt

if grep -q "fatal: bad object" changelog.txt || grep -q "fatal: bad object" delete-changelog.txt; then
    # if someone has deleted the branch of the compared git hash - git diff will fail silently
    echo "diff operation failed. Make sure the compared branch  exists"
    exit 1
fi

ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION changelog.txt delete-changelog.txt $ASSETID