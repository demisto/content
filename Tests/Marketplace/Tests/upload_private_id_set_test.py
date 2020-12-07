import logging
import os
from unittest.mock import patch

from Tests.Marketplace.upload_private_id_set import upload_private_id_set
from Tests.Marketplace.marketplace_services import GCPConfig


logger = logging.getLogger(__name__)


@patch('logging.Logger.warning')
def test_upload_private_id_set(mocker):

    dummy_storage_bucket = mocker.MagicMock()
    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET
    upload_private_id_set(dummy_storage_bucket, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             "test_data", "id_set.json"))

    mocker.assert_called_with('Finished uploading id_set.json to storage.')

    dummy_storage_bucket.name = GCPConfig.PRODUCTION_BUCKET
    upload_private_id_set(dummy_storage_bucket, '')

    mocker.assert_called_with('Skipping upload of private id set to gcs.')
