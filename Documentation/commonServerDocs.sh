python ./Documentation/extract_common_server_js.py
jsdoc2md --json ./Documentation/commonServerJsDoc.js > ./Documentation/commonServerJsDoc.json
TXT_RED="\e[31m" && TXT_CLEAR="\e[0m"
echo -e "${TXT_RED}This text is red2,${TXT_CLEAR} but this part isn't${TXT_RED} however this part is again."
python3 ./Documentation/common_server_docs.py
