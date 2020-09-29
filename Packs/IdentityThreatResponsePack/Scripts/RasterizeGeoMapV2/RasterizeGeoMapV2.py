import math

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from selenium import webdriver


def calc_midpoint(s, d):
    x1 = float(s.split(',')[0])
    y1 = float(s.split(',')[1])
    x2 = float(d.split(',')[0])
    y2 = float(d.split(',')[1])

    lat = (x1 + x2) / 2
    lon = (y1 + y2) / 2
    return str(lat) + '_' + str(lon)


src_location = demisto.args()['prev_location']
dest_location = demisto.args()['cur_location']
mid_location = calc_midpoint(src_location, dest_location)
"""
https://docs.microsoft.com/en-us/bingmaps/articles/create-a-custom-map-url
"""
base_url = "https://www.bing.com/maps?rtp=pos.{}~pos.{}&cp={}&toWww=1&lvl=1&style=r&rtop=0~1~0".format(
    src_location.replace(',', '_'), dest_location.replace(',', '_'), mid_location)
#base_url = "https://www.google.com/maps/dir/{}/{}/@{},2z".format(src_location,dest_location,mid_location)
#demisto.results(demisto.executeCommand("rasterize", {"url": base_url, "height":"1000px", "width":"2000px"}))


"""
Required for Selenium:
/docker_image_create name=selenium dependencies="selenium" packages=chromium,chromium-driver base="demisto/python3-deb:3.7.2.214"
"""
try:
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    driver = webdriver.Chrome(chrome_options=chrome_options)
    """
    Wait 13 seconds for the page to load
    """
    driver.implicitly_wait(20)
    driver.get(base_url)

    driver.save_screenshot("screenshot.png")
    driver.close()
    map_file = file_result_existing_file("screenshot.png")
    map_file['Type'] = entryTypes['image']
    demisto.results(map_file)
except Exception as ex:
    base_url = "https://www.google.com/maps/dir/{}/{}/@{},2z".format(src_location, dest_location, mid_location)
    #base_url = "https://www.google.com/maps/dir/40.409581,-3.695384/40.7060471,-74.0088901/@40.7060471,-74.0088901,3z"
    demisto.results(demisto.executeCommand("rasterize", {"url": base_url, "height": "1000px", "width": "2000px"}))
