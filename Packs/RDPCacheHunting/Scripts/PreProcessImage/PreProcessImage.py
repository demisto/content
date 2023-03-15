import cv2
import numpy as np
from PIL import Image
import io
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# sharpened
def sharpened(image):
    kernel = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, 0]], np.float32)
    kernel = 1 / 3 * kernel
    sharp = cv2.filter2D(image, -1, kernel)
    return sharp


def image_resize_big(image):
    size = 7016, 4961
    image = image.resize(size, Image.ANTIALIAS)
    # image = image.resize((8192, 6656), PIL.Image.NEAREST)
    return image


def image_resize_small(image):
    size = 1680, 1050
    image = image.resize(size, Image.ANTIALIAS)
    #  image = image.resize((8192, 6656), PIL.Image.NEAREST)
    return image


def action_grey() -> CommandResults:
    """
    Generate grayscale image.
    Returns:
        (CommandResults).
    """
    image, name = get_file_details()
    stream_gray = io.BytesIO()
    grayscale_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    final_grayscale_image = Image.fromarray(grayscale_image)
    resized_grayscale_image = image_resize_big(final_grayscale_image)
    resized_grayscale_image.save(stream_gray, format="png")
    stream_gray.seek(0)
    file_result = fileResult(f'grayscale_{name}.png', stream_gray.read())
    return CommandResults(
        outputs_prefix='PreProcessImage',
        outputs=file_result,
        raw_response=file_result
    )


def action_sharpen() -> CommandResults:
    """
    Generate sharpened image.
    Returns:
        (CommandResults).
    """
    image, name = get_file_details()
    stream_sharp = io.BytesIO()
    sharp_image = sharpened(image)
    final_sharp_image = Image.fromarray(sharp_image)
    resized_sharp_image = image_resize_big(final_sharp_image)
    resized_sharp_image.save(stream_sharp, format="png")
    stream_sharp.seek(0)
    file_result = fileResult(f'sharpened_{name}.png', stream_sharp.read())
    return CommandResults(
        outputs_prefix='PreProcessImage',
        outputs=file_result,
        raw_response=file_result
    )


def action_original() -> CommandResults:
    """
    Generate original image
    Returns:
        (CommandResults).
    """
    image, name = get_file_details()
    stream_orig = io.BytesIO()
    final_orig_image = Image.fromarray(image)
    resized_orig_image = image_resize_small(final_orig_image)
    resized_orig_image.save(stream_orig, format="jpeg")
    stream_orig.seek(0)
    file_result = fileResult(f'final_{name}.png', stream_orig.read())
    return CommandResults(
        outputs_prefix='PreProcessImage',
        outputs=file_result,
        raw_response=file_result
    )


def get_file_details():
    """
    Generate sharpened image.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (array),(str).
    """
    args = demisto.args()
    entry_id = args.get('file_entry_id')
    file = demisto.getFilePath(entry_id)
    if not file:
        raise DemistoException("Couldn't find entry id: {}".format(entry_id))
    img = cv2.imread(file['path'])
    name = file['name']
    return img, name


def main():
    try:
        args = demisto.args()
        actions = {
            'grayscale': action_grey,
            'sharpened': action_sharpen,
            'original': action_original
        }
        return_results(actions[args.get('action', '')]())
    except Exception as e:
        return_error(f'Failed to pre-process an image file. Problem: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
