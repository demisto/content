import cv2   # noqa: F401
import numpy as np
from PIL import Image
import io
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# sharpened
def sharpened(image: np.ndarray):
    """
    Sharpens image according to selected values.
    Args:
        image(np.ndarray): the image that would be sharpened.
    Returns:
        (CommandResults).
    """
    kernel = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, 0]], np.float32)
    kernel = 1 / 3 * kernel
    sharp = cv2.filter2D(image, -1, kernel)  # pylint: disable=E1101
    return sharp


def image_resize(image: Image, width: int, height: int):
    """
    REsizes image according to width and heights values.
    Args:
        image(np.ndarray): the image that would be sharpened.
        width(int): new width.
        height(int): new height.
    Returns:
        (CommandResults).
    """
    image = image.resize((width, height), Image.ANTIALIAS)
    return image


def action_grey() -> dict[str, Any]:
    """
    Generate grayscale image.
    Returns:
        (CommandResults).
    """
    args = demisto.args()
    entry_id = args.get('file_entry_id')
    width = arg_to_number(args.get('image_resize_width'))
    height = arg_to_number(args.get('image_resize_height'))
    image, name = get_file_details(entry_id)
    stream_gray = io.BytesIO()
    grayscale_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)  # pylint: disable=E1101
    final_grayscale_image = Image.fromarray(grayscale_image)
    if width and height:
        final_grayscale_image = image_resize(final_grayscale_image, width, height)
    final_grayscale_image.save(stream_gray, format="png")
    stream_gray.seek(0)
    file_result = fileResult(f'grayscale_{name}', stream_gray.read())
    return file_result


def action_sharpen() -> dict[str, Any]:
    """
    Generate sharpened image.
    Returns:
        (CommandResults).
    """
    args = demisto.args()
    entry_id = args.get('file_entry_id')
    width = arg_to_number(args.get('image_resize_width'))
    height = arg_to_number(args.get('image_resize_height'))
    image, name = get_file_details(entry_id)
    stream_sharp = io.BytesIO()
    sharp_image = sharpened(image)
    final_sharp_image = Image.fromarray(sharp_image)
    if width and height:
        final_sharp_image = image_resize(final_sharp_image, width, height)
    final_sharp_image.save(stream_sharp, format="png")
    stream_sharp.seek(0)
    file_result = fileResult(f'sharpened_{name}', stream_sharp.read())
    return file_result


def action_original() -> dict[str, Any]:
    """
    Generate original image
    Returns:
        (CommandResults).
    """
    args = demisto.args()
    entry_id = args.get('file_entry_id')
    width = arg_to_number(args.get('image_resize_width'))
    height = arg_to_number(args.get('image_resize_height'))
    image, name = get_file_details(entry_id)
    stream_orig = io.BytesIO()
    final_orig_image = Image.fromarray(image)
    if width and height:
        final_orig_image = image_resize(final_orig_image, width, height)
    final_orig_image.save(stream_orig, format="jpeg")
    stream_orig.seek(0)
    file_result = fileResult(filename=f'original_{name}', data=stream_orig.read())
    return file_result


def get_file_details(entry_id: str) -> tuple[Any, str]:
    """
    Generate sharpened image.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (array),(str).
    """
    file = demisto.getFilePath(entry_id)
    if not file:
        raise DemistoException("Couldn't find entry id: {}".format(entry_id))
    img = cv2.imread(file['path'])  # pylint: disable=E1101
    # Check if the image was successfully loaded
    if img is None:
        raise DemistoException("Could not read the image file.")
    name = os.path.splitext(file['name'])[0]
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
