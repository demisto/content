import re
from pathlib import Path
import requests  # to get image from the web
import shutil  # to save it locally

path1 = '/Users/okarkkatz/dev/demisto/content-helloworld-premium/Packs/HelloWorldPremium/README.md'
path2 = '/Users/okarkkatz/dev/demisto/content/Packs/Lansweeper/README.md'
image_url1 = 'https://raw.githubusercontent.com/crestdatasystems/content/4f707f8922d7ef1fe234a194dcc6fa73f96a4a87/Packs/Lansweeper/doc_files/Retrieve_Asset_Details_-_Lansweeper.png'


def main():
    download_image_from_endpoint(image_url1)


def replace_new_image_path():
    url_regex = r"^!\[(.*)\]\((?P<url>.*)\)"

    with open(path1) as f:
        lansweeper_lines = f.readlines()

    gcp_path = 'test_path'
    for line in lansweeper_lines:
        res = re.search(url_regex, line)
        if res:
            url = res.group('url')
            image_origin_path = Path(url)
            image_name = image_origin_path.parts[-1]
            image_gcp_path = Path(gcp_path, image_name)
            print(image_gcp_path)


def download_image_from_endpoint(image_url):
    filename = image_url.split("/")[-1]

    # Open the url image, set stream to True, this will return the stream content.
    r = requests.get(image_url, stream=True)

    # Check if the image was retrieved successfully
    if r.status_code == 200:
        # Set decode_content value to True, otherwise the downloaded image file's size will be zero.
        r.raw.decode_content = True

        # Open a local file with wb ( write binary ) permission.
        with open(filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        print('Image sucessfully Downloaded: ', filename)
    else:
        print('Image Couldn\'t be retreived')


if __name__ == '__main__':
    main()
