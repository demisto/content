import os
from google.cloud.storage.blob import Blob
from pathlib import Path
from Tests.Marketplace.marketplace_constants import GCPConfig, BucketUploadFlow
from Tests.Marketplace.pack_readme_handler import (
    copy_readme_images,
    download_readme_images_from_artifacts,
)


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
    dummy_build_bucket.copy_blob.return_value = Blob("copied_blob", dummy_prod_bucket)
    images_data = {
        BucketUploadFlow.README_IMAGES: {
            "pack1": ["image1", "image2", "image3"],
            "pack2": ["image1"],
            "pack3": ["image5", "image6"],
        }
    }
    assert copy_readme_images(
        dummy_prod_bucket,
        dummy_build_bucket,
        images_data,
        GCPConfig.CONTENT_PACKS_PATH,
        GCPConfig.BUILD_BASE_PATH,
    )


def test_download_readme_images_from_artifacts(mocker):
    readme_images_artifact_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "test_data", "readme_images.json"
    )

    mocker.patch(
        "Tests.Marketplace.pack_readme_handler.download_readme_image_from_url_and_upload_to_gcs",
        return_value=None,
    )
    pack_images_names = download_readme_images_from_artifacts(
        Path(readme_images_artifact_path), "storage_bucket"
    )
    expected_res = {
        "AWS-Enrichment-Remediation": [
            "AWS_-_Enrichment.png",
            "AWS_-_Security_Group_Remediation.png",
            "AWS_-_Security_Group_Remediation_v2.png",
            "AWS_-_Unclaimed_S3_Bucket_Validation.png",
            "AWS_-_Unclaimed_S3_Bucket_Remediation.png",
            "AWSRecreateSG.png",
        ]
    }
    assert pack_images_names == expected_res
