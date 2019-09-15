from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException

import os


def rasterize(file_name: str, path: str, width: int, height: int):
    ''''''''''''''''''''''''''''''
    # Create Chrome Driver
    ''''''''''''''''''''''''''''''
    print("Creating chrome driver")

    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--hide-scrollbars')
    chrome_options.add_argument('--disable_infobars')
    chrome_options.add_argument('--start-maximized')
    chrome_options.add_argument('--start-fullscreen')
    driver = webdriver.Chrome(options=chrome_options)

    print("Creating chrome driver - FINISHED")

    try:
        ''''''''''''''''''''''''''''''
        # Navigate to Search
        ''''''''''''''''''''''''''''''
        print("navigating to url")
        print(path)
        driver.get(url=path)
        driver.implicitly_wait(5)

        print("navigating to url - FINISHED")

        ''''''''''''''''''''''''''''''''
        # Take Screenshot and save it
        ''''''''''''''''''''''''''''''''
        print('Taking Screenshot and saving it')

        driver.set_window_size(width, height)

        driver.page_source.encode('utf-8')
        driver.get_screenshot_as_file(file_name)
        driver.quit()

        print('Taking Screenshot and saving it - FINISHED')

    except NoSuchElementException as ex:
        print("fail", str(ex))


if __name__ == '__main__':
    try:
        rasterize(file_name='screenshot.png',
                  path='file:///Users/ozohar/dev/demisto/content/Integrations/rasterize/htmlBody.html', width=1000,
                  height=1000)

        with open('htmlBody.html', 'r+') as f:
            f.write("""<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head>
            <body><br>---------- TEST FILE ----------<br></body></html>""")
            rasterize(file_name='screenshot2.png', path=f'file://{os.path.realpath(f.name)}', width=1000, height=1000)

    except Exception as ex:
        print(str(ex))
