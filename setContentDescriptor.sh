### this script populate content descriptor with correct dates and assetId

CHANGE_LOG="changelog.txt"
DELETE_CHANGE_LOG="delete-changelog.txt"
git diff --name-status $2 > "$CHANGE_LOG"
git diff  --diff-filter=D $2 > "$DELETE_CHANGE_LOG"
if [ ! -f "$CHANGE_LOG" ] || [ ! -f "$DELETE_CHANGE_LOG" ]
then
    echo "Change log files are not exist"
    exit 1
fi

ls

ASSETID=$1
VERSION=$3

python release_notes.py  $VERSION "$CHANGE_LOG" "$DELETE_CHANGE_LOG" $ASSETID