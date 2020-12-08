import os
from google.cloud.storage.blob import Blob

from Tests.Marketplace.upload_private_id_set import upload_private_id_set
from Tests.Marketplace.marketplace_services import GCPConfig


def check_path(private_id_set_gcs_path):
    assert private_id_set_gcs_path == 'content/private_id_set.json'
    blob = Blob
    return blob


def test_upload_private_id_set(mocker):

    # Skip the open and upload part
    mocker.patch('builtins.open', read_data=None)
    mocker.patch.object(Blob, 'upload_from_file', return_value=None)
    dummy_storage_bucket = mocker.Mock()
    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET
    dummy_storage_bucket.blob = check_path
    upload_private_id_set(dummy_storage_bucket, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             "test_data", "id_set.json"))
