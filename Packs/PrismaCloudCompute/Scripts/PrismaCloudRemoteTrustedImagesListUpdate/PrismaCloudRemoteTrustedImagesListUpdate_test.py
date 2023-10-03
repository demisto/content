from PrismaCloudRemoteTrustedImagesListUpdate import update_remote_trusted_images
import pytest


def test_update_remote_trusted_images():
    list_name = 'List Name'
    current_trusted_images = {}
    trusted_group_id = 'Group'
