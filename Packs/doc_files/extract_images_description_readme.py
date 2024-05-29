import os
import re
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Match,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)
from glob import glob
import os
import pandas as pd
import json

rootFolderPath = r'.'
PACKS_PATH = "/Users/mmorag/dev/demisto/content/Packs"
SAVING_IMAGES_AT = "/Users/mmorag/dev/demisto/content/Packs/doc_files/images"
URL_REGEX = r'\!\[.*?\]\((https?|ftp|https?://.*?)\)'
URL_REGEX_2 = r'\!\[.*?\]\((https?|ftp|https?://.*?png?|jpe?g|gif|bmp|tiff|webp?)\)'
'''
1. moving on all the content
2. if we run into readme/description:
2.1. search if there is an web image path:
2.1.1 create a folder with the file link 
2.1.2 download and save the image in folder {SAVING_IMAGES_AT}\{pack_name}
2.1.3 save the json file there as well
'''

def creating_info_jason(file_path:str, image_link:str, save_to_folder):
    json_info_file = open(f'{save_to_folder}\images\\{file_path}.json', 'a')
    image_details = {
                    'file_path': file_path,
                    'image_link': image_link,
                    # 'image_type': 'README' if 'README' in file_path else 'DESCRIPTION'
                }
    json.dump(image_details, json_info_file, indent=6)
    json_info_file.close()


def extract_image_link(text):
    # Regular expression to match URLs ending with common image file extensions
    image_link_pattern = r'\b\S+\.(png|jpg|jpeg|gif|bmp)\b'
    match = re.findall(URL_REGEX, text)
    return match.group(0) if match is not None else None


def download_image_to_folder(folder_path, image_path):
    print(f'Downloading image {image_path} to{folder_path}')
    # not finished


def search_image_link(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        if image_link := extract_image_link(content):
            folder_path = f'{SAVING_IMAGES_AT}\\{file_path[:-3]}'
            try:
                os.mkdir(folder_path)
                creating_info_jason(file_path, image_link, folder_path)
                download_image_to_folder(folder_path, file_path)
            except OSError as error:
                print(error)


def search_files(root_path, skip_folders = None):
    if skip_folders is None:
        skip_folders = []

    # Walk through all directories and files in the given folder path
    for root, dirs, files in os.walk(root_path):
        # Exclude specified folders from the search
        dirs[:] = [d for d in dirs if d not in skip_folders]
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower() == "readme" or file_name.lower() == "description":
                search_image_link(file_path)


def main():
    skip_folders = ["ReleaseNotes", "TestPlaybooks", "venv"]
    path = '/Users/mmorag/dev/demisto/content/Packs/Campaign'
    search_image_link('/Users/mmorag/dev/demisto/content/Packs/Campaign/README.md')
    search_files(path, skip_folders)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
