import os
import json
import fileinput
import sys


def replaceAll(file, searchExp, replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp, replaceExp)
        sys.stdout.write(line)


path_lst = [
    "Packs/DomainTools/Integrations/DomainTools/DomainTools.yml",
    ]

for file_path in path_lst:
     os.system(f'demisto-sdk update-release-notes -i {file_path} -u revision')

     names = file_path.split('/')

     # Opening JSON file
     with open(f'/Users/rshunim/dev/demisto/content/{names[0]}/{names[1]}/pack_metadata.json') as json_file:
          data = json.load(json_file)
     file_name = f'{names[0]}/{names[1]}/ReleaseNotes/{data.get("currentVersion").replace(".", "_")}.md'
     absolute_file_name = f'/Users/rshunim/dev/demisto/content/{file_name}'
     replaceAll(absolute_file_name, '%%UPDATE_RN%%', 'Updated formatting of integration parameters.')
