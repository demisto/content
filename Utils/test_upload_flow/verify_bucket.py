import argparse
import json
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


def verify_new_pack(gcp, pack_id, pack_items):
    # verify in index, verify version 1.0.0 exists in packs path
    version_exists = [gcp.is_in_index(pack_id), gcp.download_and_extract_pack(pack_id, '1.0.0')]
    items_exists = [gcp.verify_item_in_pack(pack_id, item_type, item_file_name) for item_type, item_file_name in pack_items.items()]
    return all(version_exists) and all(items_exists)


def verify_new_version(gcp, pack_id, version, rn):
    # check: RN, new version exists
    new_version_exists = gcp.download_and_extract_pack(pack_id, version)
    new_version_exists_in_changelog = gcp.get_changelog_rn_by_version(pack_id, version)
    new_version_exists_in_metadata = gcp.get_pack_metadata(pack_id)
    return all([new_version_exists, new_version_exists_in_changelog == rn, new_version_exists_in_metadata])


def verify_rn(gcp, pack_id, version, rn):
    # verify by version the content of the RN TODO: try to get the changes as input
    return gcp.get_changelog_rn_by_version(pack_id, version) == rn


def verify_hidden(gcp, pack_id):
    # verify not in index
    return not gcp.is_in_index(pack_id)


def verify_readme(gcp, pack_id, version, readme):
    # verify readme content, no version bump
    return gcp.get_max_version(pack_id) and gcp.get_pack_item(pack_id, version, '', 'README.md') == readme

def verify_pack_ignore():
    # not sure TODO: verify
    pass

def verify_landing_page():
    # not sure TODO: verify
    pass

def verify_failed_pack(gcp, pack_id):
    return gcp.get_flow_commit_hash() != gcp.get_pack_metadata(pack_id).get('commit')
    # verify commit hash is not updated
    pass

def verify_modified_pack():
    # verify new version TODO: remove since dup
    pass

def verify_modified_path(gcp, pack_id, pack_version, item_file_name):
    # verify the path of the item is modified
    return gcp.verify_item_in_pack(pack_id, pack_version, item_file_name)

def verify_dependency(gcp, pack_id, dependency_id):
    # verify the new dependency is in the metadata
    return dependency_id in gcp.get_pack_metadata(pack_id).get('dependencies').keys()
    pass

class GCP:
    def __init__(self, service_account, storage_bucket_name, storage_base_path):
        storage_client = init_storage_client(service_account)
        self.storage_bucket = storage_client.bucket(storage_bucket_name)
        self.storage_base_path = storage_base_path
        self.extracting_destination = tempfile.mkdtemp()
        self.index_path, _, _ = download_and_extract_index(self.storage_bucket, self.extracting_destination, self.storage_base_path) # fix arguments

    def download_and_extract_pack(self, pack_id, pack_version):
        pack_path = os.path.join(storage_base_path, pack_id, pack_version, f"{pack_id}.zip")
        pack = self.storage_bucket.blob(pack_path) # verify if given bad path what happens
        download_pack_path = os.path.join(self.extracting_destination, f"{pack_id}.zip")
        pack.download_to_filename(download_pack_path)
        if os.path.exists(download_pack_path):
            with ZipFile(download_pack_path, 'r') as pack_zip:
                pack_zip.extractall(self.extracting_destination)
            return os.path.join(self.extracting_destination, pack_id)
        else:
            return None

    def is_in_index(self, pack_id):
        pack_path = os.path.join(self.index_path, pack_id)
        return os.path.exists(pack_path)

    def get_changelog_rn_by_version(self, pack_id, version):
        changelog_path = os.path.join(self.index_path, pack_id, 'changelog.json')
        with open(changelog_path, 'r') as changelog_file:
            changelog = json.load(changelog_file)
        return changelog.get(version, '').get('releaseNotes')

    def get_pack_metadata(self, pack_id):
        """
        returns the metadata.json of the latest pack version from the pack's zip
        """
        metadata_path = os.path.join(self.extracting_destination, pack_id, 'metadata.json')
        with open(metadata_path, 'r') as metadata_file:
            return json.load(metadata_file)

    def is_item_in_pack(self, pack_id, item_type, item_file_name):
        # TODO: handle items that are under a subfolder
        return os.path.exists(os.path.join(self.extracting_destination, pack_id, item_type, item_file_name))

    def get_index_json(self):
        index_json_path = os.path.join(storage_base_path, 'index.json')
        index_json = self.storage_bucket.blob(index_json_path)
        download_index_path = os.path.join(self.extracting_destination, 'index.json')
        index_json.download_to_filename(download_index_path)
        with open(download_index_path, 'r') as index_json_file:
            return json.load(index_json_file)

    def get_flow_commit_hash(self):
        index_json = self.get_index_json()
        return index_json.get('commit')

    def get_max_version(self, pack_id):
        changelog = self.get_changelog(pack_id)
        return str(max([Version(key) for key, value in changelog.items()]))


    def get_changelog(self, pack_id):
        changelog_path = os.path.join(self.index_path, pack_id, 'changelog.json')
        with open(changelog_path, 'r') as changelog_file:
            return json.load(changelog_file)

    def get_pack_item(self, pack_id, item_type, item_file_name):
        item_path = os.path.join(self.extracting_destination, pack_id, item_type, item_file_name)
        with open(item_path, 'r') as f:
            return f.read()

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



if __name__ == "__main__":
    args = get_args()
    storage_base_path = args.storage_base_path
    service_account = args.service_account
    storage_bucket_name = args.bucket_name
    packs_dict = args.packs_dict  # TODO: verify parsing

    gcp_storage = GCP(service_account, storage_bucket_name, storage_base_path)
