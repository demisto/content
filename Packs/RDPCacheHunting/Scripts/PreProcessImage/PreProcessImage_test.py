from CommonServerPython import *
import pytest
from PIL import Image
import io
import cv2


IMAGE_NAME_JPG = 'test_picture_jpg.jpg'
IMAGE_PATH_JPG = 'test_data/test_picture_jpg.jpg'
IMAGE_NAME_PNG = 'test_picture_png.png'
IMAGE_PATH_PNG = 'test_data/test_picture_png.png'


IMAGE_DETAILS_CASES = [
    (IMAGE_PATH_JPG, 50, 70,
     {'format': 'JPEG', 'sizes': (50, 70)}  # expected
     ),
    (IMAGE_PATH_JPG, None, None,
     {'format': 'JPEG', 'sizes': None}  # expected
     ),
    (IMAGE_PATH_PNG, 50, 70,
     {'format': 'PNG', 'sizes': (50, 70)}  # expected
     ),
    (IMAGE_PATH_PNG, None, None,
     {'format': 'PNG', 'sizes': None}  # expected
     )
]


@pytest.mark.parametrize('path, width, height, expected_results', IMAGE_DETAILS_CASES)
def test_get_image_details(path, width, height, expected_results):
    """
    Given:
        - mocker
    When:
        - Calling function get_image_details
    Then:
        - Validate image details returned as expected
    """
    from PreProcessImage import get_image_details
    format_, sizes = get_image_details(path, width, height)
    assert format_ == expected_results['format']
    assert sizes == expected_results['sizes']


FILES_DETAILS_CASES = [
    (1, IMAGE_PATH_JPG, IMAGE_NAME_JPG, 50, 70, 'JPEG'),
    (1, IMAGE_PATH_PNG, IMAGE_NAME_PNG, 50, 70, 'PNG')
]


@pytest.mark.parametrize('entry_id, path, name, width, height, format_img', FILES_DETAILS_CASES)
def test_get_file_details(mocker, entry_id, path, name, width, height, format_img):
    """
    Given:
        - mocker
    When:
        - Calling function get_file_details
    Then:
        - Validate file details returned as expected
    """
    from PreProcessImage import get_file_details
    from unittest import mock

    def mock_file(_id):
        return {
            'path': path,
            'name': name,
        }
    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_file)
    mock_image_details = mocker.patch("PreProcessImage.get_image_details", return_value=(format_img, (width, height)))
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image
    mocker.patch('os.path.splitext', return_value=(name, format_img))
    result_img, result_name, result_img_sizes, result_img_format = get_file_details(entry_id, width, height)
    assert mock_image_details.call_count == 1
    assert result_img_sizes == (width, height)
    assert result_name == name
    assert result_img_format == format_img
    assert result_img.any()
    with Image.open(path) as origin_image:
        expected_width, expected_height = origin_image.size
    assert result_img.shape == (expected_height, expected_width, 3)


ACTION_WRAP_CASES = [
    (IMAGE_PATH_JPG, IMAGE_NAME_JPG, 'JPEG'),
    (IMAGE_PATH_JPG, IMAGE_NAME_JPG, 'JPEG'),
    (IMAGE_PATH_JPG, IMAGE_NAME_JPG, 'JPEG'),
    (IMAGE_PATH_PNG, IMAGE_NAME_PNG, 'PNG'),
    (IMAGE_PATH_PNG, IMAGE_NAME_PNG, 'PNG'),
    (IMAGE_PATH_PNG, IMAGE_NAME_PNG, 'PNG')
]


@pytest.mark.parametrize('image_path, image_name, format_img', ACTION_WRAP_CASES)
def test_grayscale(mocker, image_path, image_name, format_img):
    """
    Given:
    - An image in np.ndarray format.
    - An action to convert the image to grayscale.
    When:
    - Calling the action_wrap function.
    Then:
    - Ensure the function successfully converts the image to grayscale.
    """
    from PreProcessImage import action_wrap
    import PreProcessImage
    # Arrange
    args = {
        'action': 'grayscale',
        'file_entry_id': '1',
        'image_resize_width': None,
        'image_resize_height': None
    }
    from unittest import mock
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': image_path, 'name': image_name})
    mocker.patch.object(Image.Image, 'resize')
    mocker.patch.object(io, 'BytesIO')
    mocker.patch.object(cv2, 'cvtColor')
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image
    # Create a mock for Image.fromarray()
    mock_fromarray = mocker.patch("PIL.Image.fromarray")
    mock_final_orig_image = mock.MagicMock()
    mock_fromarray.return_value = mock_final_orig_image

    # Create a mock for io.BytesIO()
    mock_stream_orig = mock.MagicMock()
    # Create a mock for save() and seek() methods
    mocker.patch.object(mock_stream_orig, "save")
    mocker.patch.object(mock_stream_orig, "seek")
    mocker.patch.object(PreProcessImage, 'fileResult', return_value=image_path)
    # Act
    action_wrap(args)
    assert cv2.cvtColor.call_args[0][1] == cv2.COLOR_BGR2GRAY
    assert Image.fromarray.call_args[0][0] == cv2.cvtColor.return_value
    assert mock_fromarray.call_count == 1


@pytest.mark.parametrize('image_path, image_name, format_img', ACTION_WRAP_CASES)
def test_sharpened(mocker, image_path, image_name, format_img):
    """
    Given:
    - An image in np.ndarray format.
    - An action to sharpen the image.
    When:
    - Calling the action_wrap function.
    Then:
    - Ensure the function successfully sharpens the image.
    """
    import PreProcessImage
    import io
    # Arrange
    args = {
        'action': 'sharpened',
        'file_entry_id': '1',
        'image_resize_width': None,
        'image_resize_height': None
    }
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': image_path, 'name': image_name})
    mocker.patch.object(Image, 'fromarray')
    mocker.patch.object(Image.Image, 'resize')
    # mocker.patch.object(Image.Image, 'save')
    mocker.patch.object(io, 'BytesIO')
    mocker.patch.object(cv2, 'filter2D')

    def mock_file(filename, data, file_type=None):
        return {
            'Contents': '',
            'ContentsFormat': formats['text'],
            'Type': entryTypes['file'],
            'File': f'sharpened_{image_name}',
            'FileID': '1'
        }

    mocker.patch.object(PreProcessImage, 'fileResult', side_effect=mock_file)
    # Act
    result = PreProcessImage.action_wrap(args)
    # Assert
    assert result['Type'] == entryTypes['file']
    assert result['File'].startswith('sharpened_')
    assert cv2.filter2D.call_args[0][0].any()
    assert cv2.filter2D.call_args[0][1] == -1
    assert cv2.filter2D.call_args[0][2].tolist()
    assert Image.fromarray.call_args[0][0].any()
    assert Image.Image.resize.call_count == 0


@pytest.mark.parametrize('image_path, image_name, format_img', ACTION_WRAP_CASES)
def test_original(mocker, image_path, image_name, format_img):
    """
    Given:
    - An image in np.ndarray format.
    - An action to return the original image.
    When:
    - Calling the action_wrap function.
    Then:
    - Ensure the function successfully returns the original image (and not preforms sharpening or grayscale).
    """
    import PreProcessImage
    from unittest import mock
    # Arrange
    args = {
        'action': 'original',
        'file_entry_id': '1',
        'image_resize_width': 50,
        'image_resize_height': 50
    }
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': image_path, 'name': image_name})
    mocker.patch.object(Image, 'fromarray')
    mocker.patch.object(Image.Image, 'resize')
    mocker.patch.object(Image.Image, 'save')
    mocker.patch.object(io, 'BytesIO')
    # Create a mock for image_resize()
    mock_image_sharpened = mocker.patch("PreProcessImage.sharpened")
    mock_sharpened_orig_image = mock.MagicMock()
    mock_image_sharpened.return_value = mock_sharpened_orig_image

    def mock_file(filename, data, file_type=None):
        return {
            'Contents': '',
            'ContentsFormat': formats['text'],
            'Type': entryTypes['file'],
            'File': f'original_{image_name}',
            'FileID': '1'
        }

    mocker.patch.object(PreProcessImage, 'fileResult', side_effect=mock_file)
    # Act
    result = PreProcessImage.action_wrap(args)
    # Assert
    assert result['Type'] == entryTypes['file']
    assert result['File'].startswith('original_')
    assert Image.fromarray.call_args[0][0].any()
    assert mock_image_sharpened.call_count == 0
    assert Image.Image.resize.call_count == 0


def test_invalid_action(mocker):
    """
    Given:
    - An invalid action.
    When:
    - Calling the action_wrap function.
    Then:
    - Ensure the function raises a DemistoException when an invalid action is provided.
    """
    # Arrange
    from PreProcessImage import action_wrap
    args = {
        'action': 'invalid_action',
        'file_entry_id': '1',
        'image_resize_width': None,
        'image_resize_height': None}
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': IMAGE_PATH_JPG, 'name': IMAGE_NAME_JPG})
    # Act & Assert
    with pytest.raises(DemistoException):
        action_wrap(args)
