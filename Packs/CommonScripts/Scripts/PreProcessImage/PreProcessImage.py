import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import cv2   # noqa: F401
import numpy as np
from PIL import Image
import io


def sharpened(image: np.ndarray) -> np.ndarray:
    """
    Sharpens image according to selected values.
    Args:
        image(np.ndarray): the image that would be sharpened.
    Returns:
        (np.ndarray).
    """
    kernel = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, 0]], np.float32)
    kernel = 1 / 3 * kernel
    return cv2.filter2D(image, -1, kernel)  # pylint: disable=E1101


def get_image_details(path: str, width: int | None, height: int | None) -> tuple[str, Optional[tuple[int, int]]]:
    """
    Returns image details.
    Args:
        path(str): the path of the image
        width(int | None): input for the image new width if given.
        height(int | None): input for the image new height if given.
    Returns:
        (str): image format.
        (Optional[tuple[int, int]]): if width or height were given then the function would return tuple of sizes to resize to,
                                     otherwise None would be returned.
    """
    with Image.open(path) as img:
        img_format = img.format or 'png'
        img_sizes: Optional[tuple[int, int]] = None
        if width or height:
            curr_width, curr_height = img.size
            img_sizes = (width or curr_width, height or curr_height)
        return img_format, img_sizes


def get_file_details(entry_id: Optional[str], width: Optional[int], height: Optional[int]
                     ) -> tuple[Any, Any, Optional[tuple[int, int]], str]:
    """
    Gets the file details.
    Args:
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (np.ndarray): the image in np.narray format.
        (str): the name of the image.
        (tuple[int, int]): sizes to resize the image (if any were given).
        (str): image format.
    """
    file = demisto.getFilePath(entry_id)
    if not file:
        raise DemistoException(f"Couldn't find entry id: {entry_id}")
    img_format, img_sizes = get_image_details(file['path'], width, height)
    img = cv2.imread(file['path'])  # pylint: disable=E1101
    if img is None:
        # The image wasn't successfully loaded
        raise DemistoException("Could not read the image file.")
    name = os.path.splitext(file['name'])[0]
    return img, name, img_sizes, img_format


def action_wrap(args: dict) -> dict:
    """
    Preforms the selected action.
    Returns:
        FileResult (dict[str, Any]).
    """
    action = args.get('action')
    entry_id = args.get('file_entry_id')
    width = arg_to_number(args.get('image_resize_width'))
    height = arg_to_number(args.get('image_resize_height'))
    image, name, img_sizes, img_format = get_file_details(entry_id=entry_id, width=width, height=height)
    stream_buffer = io.BytesIO()
    if action == 'grayscale':
        image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)  # pylint: disable=E1101
    elif action == 'sharpened':
        image = sharpened(image)
    elif action != 'original':
        raise DemistoException('not a valid action')
    final_image = Image.fromarray(image)
    if img_sizes:
        final_image = final_image.resize(img_sizes, Image.ANTIALIAS)
    final_image.save(stream_buffer, format='png')
    stream_buffer.seek(0)
    return fileResult(f'{action}_{name}.png', stream_buffer.read())


def main():
    try:
        return_results(action_wrap(demisto.args()))
    except Exception as e:
        return_error(f'Failed to pre-process an image file. Problem: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
