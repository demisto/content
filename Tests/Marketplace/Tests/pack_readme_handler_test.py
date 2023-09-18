import os
from google.cloud.storage.blob import Blob
from pathlib import Path
from Tests.Marketplace.marketplace_constants import GCPConfig, BucketUploadFlow
from Tests.Marketplace.pack_readme_handler import (
    copy_markdown_images,
    download_markdown_images_from_artifacts,
)


def test_copy_markdown_images(mocker):
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
    dummy_build_bucket.copy_blob.return_value = Blob("copied_blob", dummy_prod_bucket)
    images_data = {
        BucketUploadFlow.MARKDOWN_IMAGES: {
            "Malwarebytes": {
                "integration_description_images": [
                    "image1.png",
                    "image2.png",
                    "image3.jpg",
                ],
                "readme_images": ["image4.png"],
            },
            "pack_2": {"readme_images": ["image5.png"]},
            "pack_3": {},
        }
    }
    assert copy_markdown_images(
        dummy_prod_bucket,
        dummy_build_bucket,
        images_data,
        GCPConfig.CONTENT_PACKS_PATH,
        GCPConfig.BUILD_BASE_PATH,
    )


def test_download_markdown_images_from_artifacts(mocker):
    readme_images_artifact_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "test_data",
        BucketUploadFlow.MARKDOWN_IMAGES_ARTIFACT_FILE_NAME,
    )

    mocker.patch(
        "Tests.Marketplace.pack_readme_handler.download_markdown_image_from_url_and_upload_to_gcs",
        return_value=None,
    )
    pack_images_names = download_markdown_images_from_artifacts(
        Path(readme_images_artifact_path), "storage_bucket", "storage_base_path"
    )
    expected_res = {
        "Malwarebytes": {
            "integration_description_images": [
                "image1.png",
                "image2.png",
                "image3.jpg",
            ],
            "readme_images": ["image4.png"],
        },
        "pack_2": {"readme_images": ["image5.png"]},
        "pack_3": {},
    }
    assert pack_images_names == expected_res
