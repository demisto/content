import os
import re
import os
import json
import requests
from pathlib import Path


rootFolderPath = r'.'
PACKS_PATH = "/Users/mmorag/dev/demisto/content/Packs"
SAVING_IMAGES_AT = "/Users/mmorag/dev/demisto/content/Packs/doc_files/images"

HTML_IMAGE_LINK_REGEX_SDK = r'(<img.*?src\s*=\s*"(https://.*?)")'
URL_IMAGE_LINK_REGEX = r'((https?|ftp)://.*?(png|jpe?g|gif|bmp|tiff|webp))'


def creating_info_jason(file_path: str, image_link: str, folder_path, pack):
    image_details = {
        'file_path': file_path,
        'image_link': image_link,
        'image_type': 'README' if 'README' in file_path else 'DESCRIPTION'
    }
    json_path = file_path[file_path.rfind(pack) + len(pack):].rsplit('/', 1)[0]
    with open(f'{folder_path}/{json_path}.json', "a") as json_file:
        json_file.write(json.dumps(image_details))


def extract_image_link(text):
    # Regular expression to match URLs ending with common image file extensions
    url_match = re.findall(URL_IMAGE_LINK_REGEX, text)
    html_match = re.findall(HTML_IMAGE_LINK_REGEX_SDK, text)
    images_links = url_match + html_match
    return images_links


def download_image_to_folder(folder_path, url):
    response = requests.get(url)
    if response.status_code == 200:
        filename = url.split('/')[-1]
        full_path = os.path.join(folder_path, filename)
        with open(full_path, 'wb') as f:
            f.write(response.content)
        print(f"Image downloaded and saved to {full_path}")
    else:
        print("Failed to download image")


def search_image_links(file_path):
    '''
        Searches for image links in the given file and downloads the images to a folder.

        Parameters:
            file_path (str): The path to the file containing text with image links.

        Returns:
            None

        Raises:
            OSError: If there is an error creating the folder to save images or downloading images.

        The function reads the content of the file located at 'file_path' and extracts image links from it.
        Then, it creates a folder to save the images and downloads each image to the folder.
        The folder name is derived from the file name by removing the extension and appending it to the specified path 'SAVING_IMAGES_AT'.
    '''
    with open(file_path, encoding='utf-8') as file:
        content = file.read()
        if image_links := extract_image_link(content):
            pack_name = re.search(r'/Packs/([^/]+)/', file_path).group(1)
            folder_path = f'{SAVING_IMAGES_AT}/{pack_name}'
            try:
                os.mkdir(folder_path)
                for image_link in image_links:
                    creating_info_jason(file_path, image_link, folder_path)
                    download_image_to_folder(folder_path, file_path)
            except OSError as error:
                print(error)


def search_files(root_path):
    readme_paths_links = list(Path(root_path).rglob("README.md"))
    description_paths_links = list(Path(root_path).rglob("description.md"))

    for link in readme_paths_links:
        search_image_links(str(link))

    for link in description_paths_links:
        search_image_links(str(link))




def main():
    path = '/Users/mmorag/dev/demisto/content/Packs/Campaign'
    search_files(path)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
