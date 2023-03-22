from CommonServerPython import *
import pytest


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
    format, sizes = get_image_details(path, width, height)
    assert format == expected_results['format']
    assert sizes == expected_results['sizes']


FILES_DETAILS_CASES = [
    (1, IMAGE_PATH_JPG, IMAGE_NAME_JPG, 50, 70, 'JPEG',
     {'format': 'JPEG', 'sizes': (50, 70)}  # expected
     ),
    (1, IMAGE_PATH_PNG, IMAGE_NAME_PNG, 50, 70, 'PNG',
     {'format': 'PNG', 'sizes': (50, 70)}  # expected
     )
]


@pytest.mark.parametrize('entry_id, path, name, width, height, format_img, expected_results', FILES_DETAILS_CASES)
def test_get_file_details(mocker, entry_id, path, name, width, height, format_img, expected_results):
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
