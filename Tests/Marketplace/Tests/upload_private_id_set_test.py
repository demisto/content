import os

from Tests.Marketplace.upload_private_id_set import upload_private_id_set
from Tests.Marketplace.marketplace_services import GCPConfig


def check_path(private_id_set_gcs_path):
    assert private_id_set_gcs_path == 'content/private_id_set.json'


def test_upload_private_id_set(mocker):

    dummy_storage_bucket = mocker.Mock()
    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET
    dummy_storage_bucket.blob = check_path
    upload_private_id_set(dummy_storage_bucket, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             "test_data", "id_set.json"))
