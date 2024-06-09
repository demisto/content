import re
import os
import json
from pathlib import Path
from urllib.parse import urlparse
PACKS_PATH = '/Users/mmorag/dev/demisto/content/Packs'
LOGS_IMAGES_PER_PACK = "/Users/mmorag/dev/demisto/content/Packs/doc_files"
HTML_IMAGE_LINK_REGEX_SDK = r'(<img.*?src\s*=\s*"(https://.*?)")'
URL_IMAGE_LINK_REGEX = r"(\!\[.*?\])\((?P<url>https://[a-zA-Z_/\.0-9\- :%]*?)\)((].*)?)"


def find_image_in_doc_files(image_name, pack_name):
    """
        Searches for a specific image file within the document files of a given pack.

        Args:
            image_name (str): The name of the image file to search for.
            pack_name (str): The name of the pack containing the document files.

        Returns:
            str: The path to the image file if found, otherwise an empty string.

        Raises:
            OSError: If there is an error while checking for the existence of the document files path.

    """
    doc_files_path = os.path.join(PACKS_PATH, pack_name)
    try:
        if os.path.exists(doc_files_path):
            return f'../../doc_files/{image_name}'
    except OSError as error:
        print(error)
    print(f"File {doc_files_path} does not exist.")
    return ''


def change_image_link_to_relative(lines, pack_name):
    # Regular expression to match URLs ending with common image file extensions
    urls_list = {"Success": [], "files not found in doc_files": []}
    for i, line in enumerate(lines):
        if res := re.search(URL_IMAGE_LINK_REGEX + r"|" + HTML_IMAGE_LINK_REGEX_SDK, line):
            url = res["url"]
            parse_url = urlparse(url)
            url_path = Path(parse_url.path)
            if new_replace_url := find_image_in_doc_files(url_path.name, pack_name):
                lines[i] = line.replace(url, new_replace_url)
                urls_list["Success"].append(url)
            else:
                urls_list["failed : files not found in doc_files"].append(url)
    return urls_list


def search_image_links(file_path):
    """
        Searches for image links in the given file and replace them to relative paths.
        Parameters:
            file_path (str): The path to the file containing text with image links.
        Returns:
            None
        Raises:
            OSError: If there is an error creating the folder to save images or downloading images.
    """
    try:
        with (open(file_path, 'w') as file):
            file_lines = file.readlines()
            if logs := change_image_link_to_relative(file_lines):
                return {file_path: logs}
    except OSError as error:
        print(error)
    return {file_path: "failed opening the file"}


def extract_image_links_from_files_and_save_to_json():
    """
    Searches for files matching a specified pattern within a directory and its subdirectories,
    then extracts image links from those files and saves the information to a JSON file.
    """
    paths_links = list(Path(PACKS_PATH).rglob("*.md"))
    images_information = {}

    for link in paths_links:
        images_information_log = search_image_links(str(link))
        if images_information_log:
            images_information[str(link)] = images_information_log

    with open(f'/Users/mmorag/dev/demisto/content/Packs/script_change_path_to_relative_MD_logs.json', "a") as file:
        file.write(json.dumps(images_information))


def main():
    try:
        extract_image_links_from_files_and_save_to_json()
    except Exception as e:
        print(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
