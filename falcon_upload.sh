# prepare & upload
demisto-sdk prepare-content -i '/Users/kqarain/dev/demisto/content/Packs/CrowdStrikeFalcon' -mp marketplacev2 --force
demisto-sdk upload -i '/Users/kqarain/dev/demisto/content/Packs/CrowdStrikeFalcon/CrowdStrikeFalcon.zip' -x

# cleanup
rm '/Users/kqarain/dev/demisto/content/Packs/CrowdStrikeFalcon/CrowdStrikeFalcon.zip'
