import re
import os
import json
from pathlib import Path
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)
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
        return os.path.exists(doc_files_path)
    except Exception as error:
        logger.debug(f"Failed to get related text file, error: {error}")
    logger.debug(f"File {doc_files_path} does not exist.")
    return False


def change_image_link_to_relative(lines, md_path):
    # Regular expression to match URLs ending with common image file extensions
    # urls_list = {"Success": [], "files not found in doc_files": []}
    list_success = []
    list_not_found = []
    parts = md_path.split("/")
    # Find the index of "Packs"
    packs_index = parts.index("Packs")

    # Extract the name after "Packs"
    pack_name = parts[packs_index + 1]
    # Modify the specific line
    for i, line in enumerate(lines):
        if res := re.search(URL_IMAGE_LINK_REGEX + r"|" + HTML_IMAGE_LINK_REGEX_SDK, line):
            url = res["url"]
            if not url:
                url = res.group(0) or res.group(1)
            parse_url = urlparse(url)
            url_path = Path(parse_url.path)
            if find_image_in_doc_files(url_path.name, pack_name):
                new_replace_url = f'doc_files/{url_path.name}'
                if "Playbooks" in md_path:
                    new_replace_url = f'../doc_files/{url_path.name}'
                elif "Integrations" in md_path:
                    new_replace_url = f'../../doc_files/{url_path.name}'
                if '<img src="' in url:
                    new_replace_url=f'<img src="{new_replace_url}'
                    list_not_found.append(url)
                lines[i] = line.replace(url, new_replace_url)
                try:
                    with open(md_path, 'w') as file:
                        file.writelines(lines)
                    list_success.append(url)
                except Exception as e:
                    logger.debug(e)
            else:
                list_not_found.append(url)
    return {"list_success": list_success, "list_not_found":list_not_found}


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
    if os.path.getsize(file_path) == 0:
        return [], [],"empty file"
    try:
        with (open(file_path, 'r+') as file):
            file_lines = file.readlines()
        if logs := change_image_link_to_relative(file_lines, file_path):
            
            return logs["list_success"], logs["list_not_found"], ''
    except Exception as error:
        logger.debug(error)
    return [], [],"failed opening the file"


def extract_image_links_from_files_and_save_to_json():
    """
    Searches for files matching a specified pattern within a directory and its subdirectories,
    then extracts image links from those files and saves the information to a JSON file.
    """
    paths_links = list(Path(PACKS_PATH).rglob("*.md"))
    paths_links_str = [str(path) for path in paths_links]
    filtered_md_files = [file for file in paths_links_str if 'ReleaseNotes' not in file.split(os.sep)]
    filtered_md_files_Playbooks = [file for file in filtered_md_files if 'Playbooks' in file.split(os.sep)]
    filtered_md_files_integrations = [file for file in filtered_md_files if 'Integrations' in file.split(os.sep)]
    filtered_md_files_without_p = [file for file in paths_links_str if 'Playbooks' not in file.split(os.sep)]
    filtered_md_files_finale = [file for file in filtered_md_files_without_p if 'Integrations' not in file.split(os.sep)]

    images_information_success = {}
    images_information_failed = {}
    _errors = {}
    for link in filtered_md_files_finale:
        
        images_information_log_success, images_information_log_fails, str_error = search_image_links(link)
        if images_information_log_success:
            images_information_success[link] = images_information_log_success
        if images_information_failed:
            images_information_failed[link] = images_information_failed
        if str_error:
            _errors[link] = str_error
    try:
        with open('/Users/mmorag/dev/demisto/content/Packs/AAA_change_image_path/success.json', "a") as file_success:
            json.dump(images_information_success, file_success, indent=4)
        with open('/Users/mmorag/dev/demisto/content/Packs/AAA_change_image_path/errors.json', "a") as file_fails:
            json.dump(images_information_failed, file_fails, indent=4)
        with open('/Users/mmorag/dev/demisto/content/Packs/AAA_change_image_path/_errors.json', "a") as errors_files:
            json.dump(_errors, errors_files, indent=4)
        with open('/Users/mmorag/dev/demisto/content/Packs/AAA_change_image_path/filtered_md_files_Playbooks.json', "a") as file_p:
            json.dump(filtered_md_files_Playbooks, file_p, indent=4)
        with open('/Users/mmorag/dev/demisto/content/Packs/AAA_change_image_path/_errors.json', "a") as errors_i:
            json.dump(filtered_md_files_integrations, errors_i, indent=4)
    except Exception as e:
        logger.debug(e)
        logger.debug(f'{_errors=}')
        logger.debug(f'{images_information_success=}')
        logger.debug(f'{images_information_failed=}')
        


def main():
    try:
        extract_image_links_from_files_and_save_to_json()
    except Exception as e:
        logger.debug(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
