import os
import re
import os
import json
import requests

rootFolderPath = r'.'
PACKS_PATH = "/Users/mmorag/dev/demisto/content/Packs"
SAVING_IMAGES_AT = "/Users/mmorag/dev/demisto/content/Packs/doc_files/images"

HTML_IMAGE_LINK_REGEX_SDK = r'(<img.*?src\s*=\s*"(https://.*?)")'
URL_IMAGE_LINK_REGEX = r'((https?|ftp)://.*?(png|jpe?g|gif|bmp|tiff|webp))'


def creating_info_jason(file_path: str, image_link: str, save_to_folder):
    json_info_file = open(f'{save_to_folder}\images\\{file_path}.json', 'a')
    image_details = {
        'file_path': file_path,
        'image_link': image_link,
        'image_type': 'README' if 'README' in file_path else 'DESCRIPTION'
    }
    json.dump(image_details, json_info_file, indent=6)
    json_info_file.close()


def extract_image_link(text):
    # Regular expression to match URLs ending with common image file extensions
    url_match = re.findall(URL_IMAGE_LINK_REGEX, text)
    html_match = re.findall(HTML_IMAGE_LINK_REGEX_SDK, text)
    images_links = url_match + html_match
    return images_links


def download_image_to_folder(folder_path, url):
    print(f'Downloading image {url} to{folder_path}')
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
            folder_path = f'{SAVING_IMAGES_AT}\\{file_path[:-3]}'
            try:
                os.mkdir(folder_path)
                for image_link in image_links:
                    creating_info_jason(file_path, image_link, folder_path)
                    download_image_to_folder(folder_path, file_path)
            except OSError as error:
                print(error)


def search_files(root_path, skip_folders=None):
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
