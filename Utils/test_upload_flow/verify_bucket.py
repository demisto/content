import argparse
import tempfile

from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.Marketplace.marketplace_services import *
if __name__ == "__main__":
    # New pack - check that pack and all its content items are there
    # Armis - check its dependency is also the new pack
    #  ZeroFox - check there is a new version and RN
    # Box - existing RN was updated
    # BPA - 1.0.0 rn was added
    # Microsoft365Defender set as hidden
    # Maltiverse - readme updated
    # MISP - update pack ignore
    # Trello - landing page
    # Absolute - failing pack
    # Alexa - modified pack TODO: verify not duplicate with zerofox
    # AlibabaActionTrail - modify item path
    # index checks
    # packs check

    pass

def verify_new_pack():
    # verify in index, verify version 1.0.0 exists in packs path
    pass

def verify_new_version():
    # check: RN, new version exists
    pass
def verify_rn():
    # verify by version the content of the RN TODO: try to get the changes as input
    pass
def verify_hidden():
    # verify not in index
    pass
def verify_readme():
    # verify readme content, no version bump
    pass
def verify_pack_ignore():
    # not sure TODO: verify
    pass
def verify_landing_page():
    # not sure TODO: verify
    pass
def verify_failed_pack():
    # verify commit hash is not updated
    pass
def verify_modified_pack():
    # verify new version
    pass
def verify_modified_path():
    # verify the path of the item is modified
    pass

# GCP class that represents the GCP data
# the GCP contains the index.zip and access to all packs by name
# verify for each pack: download by top version if no specify version

class GCP:
    def __init__(self, service_account, storage_bucket_name, storage_base_path):
        storage_client = init_storage_client(service_account)
        self.storage_bucket = storage_client.bucket(storage_bucket_name)
        self.storage_base_path = storage_base_path
        self.extracting_destination = tempfile.mkdtemp()
        self.index, _, _ = download_and_extract_index(self.storage_bucket, self.extracting_destination, self.storage_base_path) # fix arguments

    def download_and_extract_pack(self, pack_id, pack_version):
        pack_path = os.path.join(storage_base_path, pack_id, pack_version, f"{pack_id}.zip")
        pack = self.storage_bucket.blob(pack_path)
        download_pack_path = os.path.join(self.extracting_destination, f"{pack_id}.zip")
        pack.download_to_filename(download_pack_path)
        if os.path.exists(download_pack_path):
            with ZipFile(download_pack_path, 'r') as pack_zip:
                pack_zip.extractall(self.extracting_destination)
        return download_pack_path

    def is_in_index(self, pack_id):


    def get_changelog_by_version(self, version):


def get_args():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Check if the created bucket is valid")
    parser.add_argument('-s', '--service_account', help="Path to gcloud service account", required=False)
    parser.add_argument('-sb', '--storage_base_path', help="Path to storage under the marketplace-dist-dev bucket",
                        required=False)
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", default='marketplace-dist-dev')
    parser.add_argument('-p', '--packs_dict', help="Dict of pack names and versions to verify", default='marketplace-dist-dev')

    return parser.parse_args()

def verify_dependency():
    # verify the new dependency is in the metadata
    pass

if __name__ == "__main__":
    args = get_args()
    storage_base_path = args.storage_base_path
    service_account = args.service_account
    storage_bucket_name = args.bucket_name
    packs_dict = args.packs_dict  # TODO: verify parsing

    gcp_storage = GCP(service_account, storage_bucket_name, storage_base_path)
