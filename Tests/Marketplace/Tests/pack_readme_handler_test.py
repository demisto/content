import os
from google.cloud.storage.blob import Blob
from pathlib import Path
from Tests.Marketplace.marketplace_constants import GCPConfig, BucketUploadFlow
from Tests.Marketplace.pack_readme_handler import (collect_images_from_readme_and_replace_with_storage_path,
                                                   copy_readme_images,
                                                   replace_readme_urls,
                                                   download_readme_images_from_url_data_list)


def test_copy_readme_images(mocker):
    """
        Given:
            - Readme Image.
        When:
            - Performing copy and upload of all the pack's Readme images.
        Then:
            - Validate that the image has been copied from build bucket to prod bucket
    """
    dummy_build_bucket = mocker.MagicMock()
    dummy_prod_bucket = mocker.MagicMock()
    mocker.patch("Tests.Marketplace.marketplace_services.logging")
    dummy_build_bucket.copy_blob.return_value = Blob('copied_blob', dummy_prod_bucket)
    images_data = {BucketUploadFlow.README_IMAGES: {
        "pack1": ["image1", "image2", "image3"],
        "pack2": ["image1"],
        "pack3": ["image5", "image6"]
    }}
    assert copy_readme_images(dummy_prod_bucket, dummy_build_bucket, images_data,
                              GCPConfig.CONTENT_PACKS_PATH, GCPConfig.BUILD_BASE_PATH)


def test_collect_images_from_readme_and_replace_with_storage_path():
    """
        Given:
            - A README.md file with external urls
        When:
            - uploading the pack images to gcs
        Then:
            - replace the readme images url with the new path to gcs return a list of all replaces urls.
    """
    readme_images_test_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data',
                                                  'readme_images_test_data')
    path_readme_to_replace_url = os.path.join(readme_images_test_folder_path, 'url_replace_README.md')
    data = Path(os.path.join(readme_images_test_folder_path, 'original_README.md')).read_text()
    with open(path_readme_to_replace_url, 'w') as to_replace:
        to_replace.write(data)

    expected_urls_ret = {
        'original_read_me_url': 'https://raw.githubusercontent.com/crestdatasystems/content/'
                                '4f707f8922d7ef1fe234a194dcc6fa73f96a4a87/Packs/Lansweeper/doc_files/'
                                'Retrieve_Asset_Details_-_Lansweeper.png',
        'new_gcs_image_path': Path('gcs_test_path/readme_images/Retrieve_Asset_Details_-_Lansweeper.png'),
        'image_name': 'Retrieve_Asset_Details_-_Lansweeper.png',
        'pack_name': 'TestPack'
    }
    ret = collect_images_from_readme_and_replace_with_storage_path(pack_readme_path=path_readme_to_replace_url,
                                                                   gcs_pack_path='gcs_test_path',
                                                                   pack_name='TestPack',
                                                                   marketplace='marketplacev2')
    assert ret == [expected_urls_ret]

    replaced = Path(path_readme_to_replace_url).read_text()
    expected = Path(os.path.join(readme_images_test_folder_path, 'README_after_replace.md')).read_text()
    assert replaced == expected


def test_replace_readme_urls(mocker):
    mocker.patch("Tests.Marketplace.pack_readme_handler.os.listdir", return_value=['pack1', 'pack2'])
    mocker.patch("Tests.Marketplace.pack_readme_handler.os.path.exists", return_value=True)
    mocker.patch("Tests.Marketplace.pack_readme_handler.collect_images_from_readme_and_replace_with_storage_path",
                 side_effect=[[{'original_read_me_url': 'image_url1',
                               'new_gcs_image_path': 'gcp_storage_path1',
                                'image_name': 'image1'},
                              {'original_read_me_url': 'image_url2',
                                  'new_gcs_image_path': 'gcp_storage_path2',
                               'image_name': 'image2'}],
                              [{'original_read_me_url': 'image_url3',
                               'new_gcs_image_path': 'gcp_storage_path3',
                                'image_name': 'image3'}]])

    readme_images, readme_urls_data_list = replace_readme_urls(
        index_local_path='fake_index_path', storage_base_path='fake_base_path')

    readme_images_expected_result = {'pack1': ['image1', 'image2'],
                                     'pack2': ['image3']}

    readme_urls_data_list_expected_result = [{'original_read_me_url': 'image_url1',
                                              'new_gcs_image_path': 'gcp_storage_path1',
                                              'image_name': 'image1'},
                                             {'original_read_me_url': 'image_url2',
                                              'new_gcs_image_path': 'gcp_storage_path2',
                                              'image_name': 'image2'},
                                             {'original_read_me_url': 'image_url3',
                                              'new_gcs_image_path': 'gcp_storage_path3',
                                              'image_name': 'image3'}]

    assert readme_images == readme_images_expected_result
    assert readme_urls_data_list == readme_urls_data_list_expected_result


def test_download_readme_images_from_url_data_list(mocker):
    """
        Given:
            - Readme urls data list.
        When:
            - When there are different paths of readme urls.
        Then:
            - Validate that the functions are called or not according to the path type.
    """

    args_and_expected_for_test = [
        ({
            'original_read_me_url': 'https://mock.com',
            'new_gcs_image_path': Path('readme_images/test.png'),
            'image_name': 'test-test.png',
            'pack_name': 'TestPack'
        }, {'download': True, 'extract': False}),
        ({
            'original_read_me_url': 'readme_images/test.png',
            'new_gcs_image_path': Path('readme_images/test.png'),
            'image_name': 'test-test.png',
            'pack_name': 'TestPack'
        }, {'download': False, 'extract': True}),
        ({
            'original_read_me_url': 'test/test.png',
            'new_gcs_image_path': Path('readme_images/test.png'),
            'image_name': 'test-test.png',
            'pack_name': 'TestPack'
        }, {'download': False, 'extract': False})
    ]
    for test in args_and_expected_for_test:
        mock_download = mocker.patch('Tests.Marketplace.pack_readme_handler.download_readme_image_from_url_and_upload_to_gcs')
        mock_extracting = mocker.patch('Tests.Marketplace.pack_readme_handler.extracting_readme_image_from_pack_and_upload_to_gcs')
        download_readme_images_from_url_data_list([test[0]], 'test', 'test')

        assert bool(mock_download.call_count) == test[1]['download']
        assert bool(mock_extracting.call_count) == test[1]['extract']
