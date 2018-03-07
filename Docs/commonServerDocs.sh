python ./Docs/common_server_docs.py
jsdoc2md --json ./Docs/commonServerJsDoc.js > ./Docs/commonServerJsDoc.json
python ./Docs/format_js_common_server.py
