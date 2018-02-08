#!/bin/bash

USER="centos"

# collect log file to artifacts
PUBLIC_IP=$(cat public_ip)

images=(
    "demisto/python3" 
    "demisto/bs4" 
    "demisto/dxl" 
    "demisto/nmap" 
    "demisto/psycopg2"
    "demisto/rasterize"
    "demisto/splunksdk:1.0"
    "demisto/symantec_mss"
    "demisto/pytan"
    "demisto/threatconnect-sdk"
    "demisto/vmray"
    "demisto/vmware:1.0-alpine"
    "demisto/machine-learning:latest"
    "demisto/langdetect"
    "demisto/word-parser"
    "demisto/trorabaugh/dempcap:1.0"
    "demisto/pypdf2"
    "demisto/pyping"
    "demisto/pdfx"
    "demisto/stix"
    "demisto/unrar:1.4"
)

for i in ${images[@]}; do
    ssh -t ${USER}@${PUBLIC_IP} "sudo docker pull ${i}"
done