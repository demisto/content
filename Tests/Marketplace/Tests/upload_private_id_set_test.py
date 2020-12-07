import os
from google.cloud import storage

from Tests.Marketplace.upload_private_id_set import upload_private_id_set
from Tests.Marketplace.marketplace_services import GCPConfig


def test_upload_private_id_set(mocker):

    dummy_storage_bucket = mocker.MagicMock()
    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET
    upload_private_id_set(dummy_storage_bucket, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             "test_data", "id_set.json"))
    storage_client = storage.Client()
    stats = storage.Blob(bucket=dummy_storage_bucket, name=dummy_storage_bucket.name).exists(storage_client)
    assert stats
