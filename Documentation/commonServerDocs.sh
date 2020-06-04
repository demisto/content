python ./Documentation/extract_common_server_js.py
jsdoc2md --json ./Documentation/commonServerJsDoc.js > ./Packs/Base/Docs/commonServerJsDoc.json
python3 ./Documentation/common_server_docs.py
