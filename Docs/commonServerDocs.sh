python ./Docs/extract_common_Server_js.py
sleep 5
jsdoc2md --json ./Docs/commonServerJsDoc.js > ./Docs/commonServerJsDoc.json
python ./Docs/common_server_docs.py
