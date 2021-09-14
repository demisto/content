python ./Documentation/extract_common_server_js.py
jsdoc2md --json ./Documentation/commonServerJsDoc.js > ./Documentation/commonServerJsDoc.json
python3 ./Documentation/common_server_docs.py
