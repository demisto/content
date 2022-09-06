import argparse
import json
import tempfile

from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.Marketplace.marketplace_services import *


class BucketVerifier:
    def __init__(self, gcp, versions_dict):
        self.gcp = gcp
        self.versions = versions_dict
        self.is_valid = True

    def verify_new_pack(self, pack_id, pack_items):
        # verify in index, verify version 1.0.0 exists in packs path
        version_exists = [self.gcp.is_in_index(pack_id), self.gcp.download_and_extract_pack(pack_id, '1.0.0')]
        items_exists = [self.gcp.is_item_in_pack(pack_id, item_type, item_file_name) for item_type, item_file_name in pack_items.items()]
        self.is_valid = self.is_valid and all(version_exists) and all(items_exists)

    def verify_modified_pack(self, pack_id, pack_items):
        version_exists = [self.gcp.is_in_index(pack_id), self.gcp.download_and_extract_pack(pack_id, self.versions[pack_id])]
        items_exists = [self.gcp.is_item_in_pack(pack_id, item_type, item_file_name) for item_type, item_file_name in
                        pack_items.items()]
        self.is_valid = self.is_valid and all(version_exists) and all(items_exists)

    def verify_new_version(self, pack_id, rn):
        # check: RN, new version exists
        new_version_exists = self.gcp.download_and_extract_pack(pack_id, self.versions[pack_id])
        new_version_exists_in_changelog = self.gcp.get_changelog_rn_by_version(pack_id, self.versions[pack_id])
        new_version_exists_in_metadata = self.gcp.get_pack_metadata(pack_id)
        self.is_valid = self.is_valid and all([new_version_exists, new_version_exists_in_changelog == rn, new_version_exists_in_metadata])

    def verify_rn(self, pack_id, rn):
        # verify by version the content of the RN TODO: try to get the changes as input
        self.is_valid = self.is_valid and self.gcp.get_changelog_rn_by_version(pack_id, self.versions[pack_id]) == rn

    def verify_hidden(self, pack_id):
        # verify not in index
        self.is_valid = self.is_valid and not self.gcp.is_in_index(pack_id)

    def verify_readme(self, pack_id, readme):
        # verify readme content, no version bump
        self.is_valid = self.is_valid and gcp.get_max_version(pack_id) and self.gcp.get_pack_item(pack_id, self.versions[pack_id], '', 'README.md') == readme

    def verify_pack_ignore(self, pack_id):
        # not sure TODO: verify
        pass

    def verify_landing_page(self, pack_id):
        # not sure TODO: verify
        pass

    def verify_failed_pack(self, pack_id):
        # verify commit hash is not updated
        self.is_valid = self.is_valid and self.gcp.get_flow_commit_hash() != self.gcp.get_pack_metadata(pack_id).get('commit')

    def verify_modified_pack(self):
        # verify new version TODO: remove since dup
        pass

    def verify_modified_path(self, pack_id, item_type, item_file_name, extension):
        # verify the path of the item is modified
        self.is_valid = self.is_valid and self.gcp.is_item_in_pack(pack_id, item_type, item_file_name, extension)

    def verify_dependency(self, pack_id, dependency_id):
        # verify the new dependency is in the metadata
        self.is_valid = self.is_valid and dependency_id in \
                        self.gcp.get_pack_metadata(pack_id).get('dependencies').keys()


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

    def is_item_in_pack(self, pack_id, item_type, item_file_name, extension):
        """
        Check if an item is inside the pack. this function is suitable for content items that
        have a subfolder (for example: Integrations/ObjectName/integration-ObjectName.yml
        """
        return os.path.exists(os.path.join(self.extracting_destination, pack_id, item_type, item_file_name,
                                           f'{item_type.to_lower()[:-1]}-{item_file_name}.{extension}'))

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
    versions_dict = args.version_dict  # TODO: verify parsing, should be pack_id: version of the modified pack or RN
    items_dict = args.items_dict  # TODO: verify parsing, should be pack_id: {item_type: item_id} of the modified pack or RN
    gcp = GCP(service_account, storage_bucket_name, storage_base_path)

    bv = BucketVerifier(gcp, versions_dict)
    # verify new pack - TestUploadFlow
    bv.verify_new_pack('TestUploadFlow', items_dict.get('TestUploadFlow'))

    # verify dependencies handling
    bv.verify_dependency('Armis', 'TestUploadFlow')

    # verify new version
    expected_rn = ''  # TODO: add from branch script
    bv.verify_new_version('ZeroFox', expected_rn)

    # verify modified existing rn
    expected_rn = ''  # TODO: add from branch script
    bv.verify_rn('Box', expected_rn)

    # verify 1.0.0 rn was added
    expected_rn = ''  # TODO: add from branch script
    bv.verify_rn('BPA', expected_rn)

    # verify pack is set to hidden
    bv.verify_hidden('Microsoft365Defender')

    # verify readme
    expected_readme = '' # TODO: add
    bv.verify_readme('Maltiverse', expected_readme)

    # verify pack ignore
    bv.verify_pack_ignore('MISP') # TODO: fix

    # verify landingpage
    bv.verify_landing_page('Trello') # TODO: fix

    # verify failing pack
    bv.verify_failed_pack('Absolute')

    # verify path modification
    bv.verify_modified_path('AlibabaActionTrail', 'ModelingRule', 'Alibaba', 'yml')
    bv.verify_modified_path('AlibabaActionTrail', 'ModelingRule', 'Alibaba', 'jsom')
    bv.verify_modified_path('AlibabaActionTrail', 'ModelingRule', 'Alibaba', 'xif')

    # verify modified pack
    bv.verify_modified_pack('Alexa', items_dict.get('Alexa'))

