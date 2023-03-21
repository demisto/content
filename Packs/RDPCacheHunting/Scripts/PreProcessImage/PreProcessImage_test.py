from CommonServerPython import *
from PIL import Image
import cv2


IMAGE_NAME = 'test_picture.jpg'
IMAGE_PATH = 'test_data/test_picture.jpg'
ORIGIN_IMG = Image.open(IMAGE_PATH)
IMG = cv2.imread(IMAGE_PATH)


def test_get_file_details(mocker):
    """
    Given:
        - mocker
    When:
        - Calling function get_file_details
    Then:
        - Validate file details returned as expected
    """
    from PreProcessImage import get_file_details

    def mock_file(_id):
        return {
            'path': IMAGE_PATH,
            'name': IMAGE_NAME,
        }
    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_file)
    img, name = get_file_details(IMAGE_NAME)
    width, height = ORIGIN_IMG.size
    assert name == 'test_picture'
    assert img.shape == (height, width, 3)


def test_action_original(mocker):
    """
    Given:
        - mocker
    When:
        - Calling function action_original
    Then:
        - Validate file details returned as expected
    """
    from PreProcessImage import action_original
    from unittest import mock
    mocker.patch.object(demisto, 'args', return_value={'file_entry_id': IMAGE_NAME,
                                                       'image_resize_width': 7016,
                                                       'image_resize_height': 4961})
    # from PIL import Image
    mocker.patch('PreProcessImage.get_file_details', return_value=(IMG, IMAGE_NAME))
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image

    # Create a mock for image_resize_small()
    mock_image_resize_small = mocker.patch("PreProcessImage.image_resize")
    mock_resized_orig_image = mock.MagicMock()
    mock_image_resize_small.return_value = mock_resized_orig_image

    # Create a mock for io.BytesIO()
    mock_stream_orig = mock.MagicMock()
    # Create a mock for save() and seek() methods
    mock_save = mocker.patch.object(mock_resized_orig_image, "save")
    mock_seek = mocker.patch.object(mock_stream_orig, "seek")
    mocker.patch('CommonServerPython.fileResult', return_value={IMAGE_NAME: 'test'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    action_original()
    assert mock_save.call_count == 1
    assert mock_fromarray.call_count == 1
    assert mock_image_resize_small.call_count == 1
    assert mock_seek


def test_action_sharpen(mocker):
    """
    Given:
        - mocker
    When:
        - Calling function action_sharpen
    Then:
        - Validate file details returned as expected
    """
    from PreProcessImage import action_sharpen
    from unittest import mock
    mocker.patch.object(demisto, 'args', return_value={'file_entry_id': IMAGE_NAME,
                                                       'image_resize_width': 7016,
                                                       'image_resize_height': 4961})
    # from PIL import Image
    mocker.patch('PreProcessImage.get_file_details', return_value=(IMG, IMAGE_NAME))
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image

    # Create a mock for image_resize()
    mock_image_resize = mocker.patch("PreProcessImage.image_resize")
    mock_resized_orig_image = mock.MagicMock()
    mock_image_resize.return_value = mock_resized_orig_image

    # Create a mock for io.BytesIO()
    mock_stream_orig = mock.MagicMock()
    # Create a mock for save() and seek() methods
    mock_save = mocker.patch.object(mock_resized_orig_image, "save")
    mock_seek = mocker.patch.object(mock_stream_orig, "seek")
    mocker.patch('CommonServerPython.fileResult', return_value={IMAGE_NAME: 'test'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    action_sharpen()
    assert mock_save.call_count == 1
    assert mock_fromarray.call_count == 1
    assert mock_image_resize.call_count == 1
    assert mock_seek


def test_action_grey(mocker):
    """
    Given:
        - mocker
    When:
        - Calling function action_sharpen
    Then:
        - Validate file details returned as expected
    """
    from PreProcessImage import action_grey
    from unittest import mock
    mocker.patch.object(demisto, 'args', return_value={'file_entry_id': IMAGE_NAME,
                                                       'image_resize_width': 7016,
                                                       'image_resize_height': 4961})
    # from PIL import Image
    mocker.patch('PreProcessImage.get_file_details', return_value=(IMG, IMAGE_NAME))
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image

    # Create a mock for image_resize_big()
    mock_image_resize = mocker.patch("PreProcessImage.image_resize")
    mock_resized_orig_image = mock.MagicMock()
    mock_image_resize.return_value = mock_resized_orig_image

    # Create a mock for io.BytesIO()
    mock_stream_orig = mock.MagicMock()
    # Create a mock for save() and seek() methods
    mock_save = mocker.patch.object(mock_resized_orig_image, "save")
    mock_seek = mocker.patch.object(mock_stream_orig, "seek")
    mocker.patch('CommonServerPython.fileResult', return_value={IMAGE_NAME: 'test'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    action_grey()
    assert mock_save.call_count == 1
    assert mock_fromarray.call_count == 1
    assert mock_image_resize.call_count == 1
    assert mock_seek
