import re
from pathlib import Path
import requests  # to get image from the web
import shutil  # to save it locally
import fileinput
import urllib.parse

path1 = '/Users/okarkkatz/dev/demisto/content/hello_world_premium_readme.md'
path2 = '/Users/okarkkatz/dev/demisto/content/replace_README.md'
image_url1 = 'https://raw.githubusercontent.com/crestdatasystems/content/4f707f8922d7ef1fe234a194dcc6fa73f96a4a87/Packs/Lansweeper/doc_files/Retrieve_Asset_Details_-_Lansweeper.png'
image_permium = 'https://github.com/demisto/content-helloworld-premium/blob/master/Packs/HelloWorldPremium/doc_files/HelloWorldPremium_Scan.png?raw=true'

def main():
    # urls_found = replace_new_image_path()
    # for url in urls_found:
    download_image_from_endpoint(image_permium)

    # download_image_from_endpoint(image_url1)



def replace_new_image_path():
    url_regex = r"^!\[(.*)\]\((?P<url>.*)\)"

    for line in fileinput.input(path1, inplace=True):
        gcp_path = 'https://test_path'
        res = re.search(url_regex, line)
        urls_list = []
        if res:
            url = res.group('url')
            image_origin_path = Path(url)
            image_name = image_origin_path.parts[-1]
            image_gcp_path = Path(gcp_path, image_name)
            line = line.replace(url, str(image_gcp_path))
            urls_list.append(str(image_origin_path))

        print(line, end='')
    return urls_list


def download_image_from_endpoint(image_url):

    # params_dict = dict(parse.parse_qsl(parse.urlsplit(image_url).query))
    # url_without_params = parse.splitquery(image_url)[0]
    # filename = url_without_params.split("/")[-1]
    parse_url = urllib.parse.urlparse(image_url)
    path = parse_url.path
    url_path = Path(path)
    filename = url_path.name
    # Open the url image, set stream to True, this will return the stream content.
    r = requests.get(image_url, stream=True, verify=False)

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
