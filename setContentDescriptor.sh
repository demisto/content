### this script populate content descriptor with correct dates and assetId

ASSETID=$1
RELEASE_DATE=`date +"%m-%d-%yT%T.0%z"`

sed -i -- "s/REPLACE_THIS_WITH_CI_BUILD_NUM/$ASSETID/g" ./content-descriptor.json*
sed -i -- "s/REPLACE_THIS_WITH_RELEASE_DATE/$RELEASE_DATE/g" ./content-descriptor.json*
