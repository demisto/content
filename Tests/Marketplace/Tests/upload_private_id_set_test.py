import os
from google.cloud.storage.blob import Blob

from Tests.Marketplace.upload_private_id_set import upload_private_id_set_to_bucket
from Tests.Marketplace.marketplace_services import GCPConfig


def test_upload_private_id_set(mocker):
    """
    Given
    - private ID set to upload
    When
    - upload
    Then
    - ensure that the private ID set uploaded to the exact path we want it to upload
    """

    # Skip the open and upload part
    mocker.patch('builtins.open', read_data=None)
    mocker.patch.object(Blob, 'upload_from_file', return_value=None)

    dummy_storage_bucket = mocker.Mock()
    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET

    def check_path(private_id_set_gcs_path):
        assert private_id_set_gcs_path == 'private_id_set.json'
        return Blob

    dummy_storage_bucket.blob = check_path
    upload_private_id_set_to_bucket(dummy_storage_bucket, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                       "test_data", "id_set.json"))
