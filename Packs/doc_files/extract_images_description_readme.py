import os
import re
import os
import json
import requests
from pathlib import Path
from urllib.parse import urlparse

PACKS_PATH = '/Users/mmorag/dev/demisto/content/Packs'
LOGS_IMAGES_PER_PACK = "/Users/mmorag/dev/demisto/content/Packs/doc_files"
HTML_IMAGE_LINK_REGEX_SDK = r'(<img.*?src\s*=\s*"(https://.*?)")'
URL_IMAGE_LINK_REGEX = r"(\!\[.*?\])\((?P<url>https://[a-zA-Z_/\.0-9\- :%]*?)\)((].*)?)"


def extract_image_link(lines, final_dst_image_path, original_file_path):
    # Regular expression to match URLs ending with common image file extensions
    urls_list = []
    for i, line in enumerate(lines):
        if res := re.search(URL_IMAGE_LINK_REGEX, line):
            url = res.group("url")
            # parse_url = urlparse(url)
            urls_list.append(url)
    return urls_list


def download_image_to_folder(folder_path, url):
    """
    Downloads an image from a given URL and saves it to a specified folder.

    Args:
        folder_path (str): The path to the folder where the image will be saved.
        url (str): The URL of the image to be downloaded.

    Returns:
        int: The HTTP status code of the response. 200 indicates success.
    """
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        filename = url.split('/')[-1]
        full_path = os.path.join(folder_path, filename)
        with open(full_path, 'wb') as f:
            f.write(response.content)
        print(f"Image downloaded and saved to {full_path}")  # for debugging, removing it later
    else:
        print("Failed to download image")  # for debugging, removing it later
    return response.status_code


def search_image_links(file_path):
    """
        Searches for image links in the given file and downloads the images to a folder.

        Parameters:
            file_path (str): The path to the file containing text with image links.

        Returns:
            None

        Raises:
            OSError: If there is an error creating the folder to save images or downloading images.
    """
    images_information_dict = {'Image successfully downloaded': [],
                               'Failed to download image': []}
    with (open(file_path, encoding='utf-8') as file):
        file_lines = file.readlines()
        pack_name = re.search(r'/Packs/([^/]+)/', file_path).group(1)
        folder_path = f'/Users/mmorag/dev/demisto/content/Packs/{pack_name}/doc_files'
        if image_links := extract_image_link(file_lines, folder_path, file_path):
            if not os.path.exists(folder_path):
                try:
                    os.makedirs(folder_path)
                except OSError as error:
                    print(error)
            for image_link in image_links:
                status = download_image_to_folder(folder_path, image_link)
                if status == 200:
                    images_information_dict['Image successfully downloaded'].append(image_link)
                else:
                    images_information_dict['Failed to download image'].append({'image_link': image_link,
                                                                                'status': status})
            images_information_dict['Total Downloaded'] = len(images_information_dict['Image successfully downloaded'])
            return images_information_dict


def extract_image_links_from_files_and_save_to_json():
    """
    Searches for files matching a specified pattern within a directory and its subdirectories,
    then extracts image links from those files and saves the information to a JSON file.

    Args:
        pattern_to_search (str): The pattern to search for in file names.
        json_file_name (str): The name for the JSON file to save the images information.
    """
    paths_links = list(Path(PACKS_PATH).rglob("*.md"))
    images_information = {}

    for link in paths_links:
        images_information_log = search_image_links(str(link))
        if images_information_log:
            images_information[str(link)] = images_information_log

    with open(f'/Users/mmorag/dev/demisto/content/Packs/doc_files/logs_images_info.json', "a") as file:
        file.write(json.dumps(images_information))


def main():
    try:
        extract_image_links_from_files_and_save_to_json()
    except Exception as e:
        print(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
