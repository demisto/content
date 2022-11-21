import argparse
import functools
import json
import logging
import os
import tempfile

from Tests.Marketplace.marketplace_services import *
from Tests.Marketplace.upload_packs import download_and_extract_index
from Tests.scripts.utils.log_util import install_logging

install_logging('create_test_branch.log', logger=logging)

MSG_DICT = {
    'verify_new_pack': 'Verify the pack is in the index, verify version 1.0.0 zip exists under the pack path',
    'verify_modified_pack': 'Verify the packs new version is in the index, verify the new version zip exists under '
                            'the packs path, verify all the new items are present in the pack',
    'verify_new_version': 'Verify a new version exists in the index, verify the rn is parsed correctly to the '
                          'changelog',
    'verify_rn': 'Verify the content of the RN is in the changelog under the right version',
    'verify_hidden': 'Verify the pack does not exist in index',
    'verify_readme': 'Verify readme content is parsed correctly, verify that there was no version bump '
                     'if only readme was modified',
    'verify_failed_pack': 'Verify commit hash is not updated in the pack metadata in the index.zip',
    'verify_modified_path': 'Verify the path of the item is modified',
    'verify_dependency': 'Verify the new dependency is in the metadata',
    'verify_new_image': 'Verify the new image was uploaded'
}


def logger(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        #logging.info(f'Starting {func.__name__}')
        print(f'Starting {func.__name__}')
        try:
            result, pack_id = func(self, *args, **kwargs)
            self.is_valid = self.is_valid and result
            #logging.info(f'Result of {func.__name__} - {MSG_DICT[func.__name__]} for {pack_id} is {result}')
            print(f'Result of {func.__name__} - {MSG_DICT[func.__name__]} for {pack_id} is {result}') # TODO: remove all prints once logging is present in the gitlab build
        except FileNotFoundError as e:
            #logging.info(f'Result of {func.__name__} - {MSG_DICT[func.__name__]} is False: {e}')
            print(f'Result of {func.__name__} - {MSG_DICT[func.__name__]} is False: {e}')
            self.is_valid = False

    return wrapper


class GCP:
    def __init__(self, service_account, storage_bucket_name, storage_base_path):
        storage_client = init_storage_client(service_account)
        self.storage_bucket = storage_client.bucket(storage_bucket_name)
        self.storage_base_path = storage_base_path

        self.extracting_destination = tempfile.mkdtemp()
        self.index_path, _, _ = download_and_extract_index(self.storage_bucket, self.extracting_destination, self.storage_base_path)
        # TODO: for testing, use these lines instead of the 2 above
        # self.extracting_destination = os.path.join(os.getcwd(), 'results')
        # self.index_path = '/Users/nmaimon/dev/demisto/content/Utils/test_upload_flow/results/index' TODO: download the index once to this path and then work with it, instead of downloading it again and again

    def download_and_extract_pack(self, pack_id, pack_version):
        pack_path = os.path.join(self.storage_base_path, pack_id, pack_version, f"{pack_id}.zip")
        pack = self.storage_bucket.blob(pack_path)
        if pack.exists():
            download_pack_path = os.path.join(self.extracting_destination, f"{pack_id}.zip")
            pack.download_to_filename(download_pack_path)
            with ZipFile(download_pack_path, 'r') as pack_zip:
                pack_zip.extractall(os.path.join(self.extracting_destination, pack_id))
            return os.path.join(self.extracting_destination, pack_id)
        else:
            raise FileNotFoundError(f'{pack_id} pack of version {pack_version} was not found in the bucket')

    def download_image(self, pack_id):
        image_path = os.path.join(storage_base_path, pack_id, f"{pack_id}_image.png")
        image = self.storage_bucket.blob(image_path)
        if image.exists():
            download_image_path = os.path.join(self.extracting_destination, f"{pack_id}_image.png")
            image.download_to_filename(download_image_path)
            return download_image_path
        else:
            raise FileNotFoundError(f'Image of pack {pack_id} was not found in the bucket')

    def is_in_index(self, pack_id):
        pack_path = os.path.join(self.index_path, pack_id)
        return os.path.exists(pack_path)

    def get_changelog_rn_by_version(self, pack_id, version):
        changelog_path = os.path.join(self.index_path, pack_id, 'changelog.json')
        changelog = read_json(changelog_path)
        return changelog.get(version, {}).get('releaseNotes', '')

    def get_pack_metadata(self, pack_id):
        """
        returns the metadata.json of the latest pack version from the pack's zip
        """
        metadata_path = os.path.join(self.extracting_destination, 'index', pack_id, 'metadata.json')
        return read_json(metadata_path)

    def is_item_in_pack(self, pack_id, item_type, item_file_path):
        """
        Check if an item is inside the pack.
        """
        item_name_with_extension = Path(item_file_path).name
        extracted_item_path = os.path.join(self.extracting_destination, pack_id, item_type,
                                               item_name_with_extension)
        exists = os.path.exists(extracted_item_path)
        return exists

    def get_index_json(self):
        index_json_path = os.path.join(storage_base_path, 'index.json')
        index_json = self.storage_bucket.blob(index_json_path)
        if index_json.exists():
            download_index_path = os.path.join(self.extracting_destination, 'index.json')
            index_json.download_to_filename(download_index_path)
            return read_json(download_index_path)
        else:
            raise FileNotFoundError('index.json was not found in the bucket')

    def get_flow_commit_hash(self):
        index_json = self.get_index_json()
        return index_json.get('commit')

    def get_max_version(self, pack_id):
        changelog = self.get_changelog(pack_id)
        return str(max([Version(key) for key, value in changelog.items()]))

    def get_changelog(self, pack_id):
        changelog_path = os.path.join(self.index_path, pack_id, 'changelog.json')
        return read_json(changelog_path)

    def get_pack_readme(self, pack_id):
        item_path = os.path.join(self.extracting_destination, pack_id, 'README.md')
        with open(item_path, 'r') as f:
            return f.read()

class BucketVerifier:
    def __init__(self, gcp: GCP, versions_dict):
        self.gcp = gcp
        self.versions = versions_dict
        self.is_valid = True

    @logger
    def verify_new_pack(self, pack_id, pack_items):
        """
        Verify the pack is in the index, verify version 1.0.0 zip exists under the pack's path
        """
        version_exists = [self.gcp.is_in_index(pack_id), self.gcp.download_and_extract_pack(pack_id, '1.0.0')]
        items_exists = [self.gcp.is_item_in_pack(pack_id, item_type, item_file_path) for item_type, item_file_path
                        in pack_items.items()]
        return all(version_exists) and all(items_exists), pack_id

    @logger
    def verify_modified_pack(self, pack_id, pack_items):
        """
        Verify the pack's new version is in the index, verify the new version zip exists under the pack's path,
        verify all the new items are present in the pack
        """
        pack_path = self.gcp.download_and_extract_pack(pack_id, self.versions[pack_id])
        version_exists = [self.gcp.get_changelog_rn_by_version(pack_id, self.versions[pack_id])]
        items_exists = [get_items_dict(pack_path, pack_id) == pack_items]
        return all(version_exists) and all(items_exists), pack_id

    @logger
    def verify_new_version(self, pack_id, rn):
        """
        Verify a new version exists in the index, verify the rn is parsed correctly to the changelog
        """
        new_version_exists = self.gcp.download_and_extract_pack(pack_id, self.versions[pack_id])
        new_version_exists_in_changelog = rn in self.gcp.get_changelog_rn_by_version(pack_id, self.versions[pack_id])
        new_version_exists_in_metadata = self.gcp.get_pack_metadata(pack_id).get('currentVersion') == self.versions[pack_id]
        return all([new_version_exists, new_version_exists_in_changelog, new_version_exists_in_metadata]), pack_id

    @logger
    def verify_rn(self, pack_id, rn):
        """
        Verify the content of the RN is in the changelog under the right version
        """
        return rn in self.gcp.get_changelog_rn_by_version(pack_id, self.versions[pack_id]), pack_id

    @logger
    def verify_hidden(self, pack_id):
        """
        Verify the pack does not exist in index
        """
        return not self.gcp.is_in_index(pack_id), pack_id

    @logger
    def verify_readme(self, pack_id, readme):
        """
        Verify readme content is parsed correctly, verify that there was no version bump if only readme was modified
        """
        gcp.download_and_extract_pack(pack_id, self.versions[pack_id])
        return gcp.get_max_version(pack_id) and readme in self.gcp.get_pack_readme(pack_id), pack_id

    @logger
    def verify_failed_pack(self, pack_id):
        """
        Verify commit hash is not updated in the pack's metadata in the index.zip
        """
        return self.gcp.get_flow_commit_hash() != self.gcp.get_pack_metadata(pack_id).get('commit'), pack_id

    @logger
    def verify_modified_path(self, item_type, pack_id, item_file_path):
        """
        Verify the path of the item is modified
        """

        gcp.download_and_extract_pack(pack_id, self.versions[pack_id])
        return self.gcp.is_item_in_pack(pack_id, item_type, item_file_path), pack_id

    @logger
    def verify_dependency(self, pack_id, dependency_id):
        """
        Verify the new dependency is in the metadata
        """
        return dependency_id in self.gcp.get_pack_metadata(pack_id).get('dependencies', {}).keys(), pack_id

    @logger
    def verify_new_image(self, pack_id, new_image_path):
        """
        Verify the new image was uploaded
        """
        image_in_bucket_path = gcp.download_image(pack_id)
        return open(image_in_bucket_path, "rb").read() == open(str(new_image_path), "rb").read(), pack_id


def get_items_dict(pack_path, pack_id):
    pack = Pack(pack_id, pack_path)
    pack.collect_content_items()
    return pack._content_items


def get_args():
    parser = argparse.ArgumentParser(description="Check if the created bucket is valid")
    parser.add_argument('-s', '--service-account', help="Path to gcloud service account", required=False)
    parser.add_argument('-sb', '--storage-base_path', help="Path to storage under the marketplace-dist-dev bucket",
                        required=False)
    parser.add_argument('-b', '--bucket-name', help="Storage bucket name", default='marketplace-dist-dev')
    parser.add_argument('-a', '--artifacts-path', help="path to artifacts from the script creating the test branch, "
                                                       "should contain json with dict of pack names and items to verify"
                                                       "and json with dict of pack names and versions to verify",
                        required=False)

    return parser.parse_args()


def read_json(path):
    with open(path, 'r') as file:
        return json.load(file)


if __name__ == "__main__":
    args = get_args()
    storage_base_path = args.storage_base_path
    service_account = args.service_account
    storage_bucket_name = args.bucket_name
    versions_dict = read_json(os.path.join(args.artifacts_path, 'versions_dict.json'))
    items_dict = read_json(os.path.join(args.artifacts_path, 'packs_items.json'))
    gcp = GCP(service_account, storage_bucket_name, storage_base_path)

    bv = BucketVerifier(gcp, versions_dict)
    # Case 1: Verify new pack - TestUploadFlow
    bv.verify_new_pack('TestUploadFlow', items_dict.get('TestUploadFlow'))

    # Case 2: Verify dependencies handling - Armis
    bv.verify_dependency('Armis', 'TestUploadFlow')

    # Case 3: Verify new version - ZeroFox
    expected_rn = 'testing adding new RN'
    bv.verify_new_version('ZeroFox', expected_rn)

    # Case 4: Verify changed image - Armis
    bv.verify_new_image('Armis', Path(
        __file__).parent / 'TestUploadFlow' / 'Integrations' / 'TestUploadFlow' / 'TestUploadFlow_image.png')

    # Case 5: Verify modified existing release notes - Box
    expected_rn = 'testing modifying existing RN'
    bv.verify_rn('Box', expected_rn)

    # Case 6: Verify 1.0.0 rn was added - BPA
    expected_rn = """\n#### Integrations\n##### BPA\nfirst release note\n"""
    bv.verify_rn('BPA', expected_rn)

    # Case 7: Verify pack is set to hidden - Microsoft365Defender
    # bv.verify_hidden('Microsoft365Defender')  TODO: fix after hidden pack mechanism is fixed

    # Case 8: Verify changed readme - Maltiverse
    expected_readme = 'readme test upload flow'
    bv.verify_readme('Maltiverse', expected_readme)

    # Case 9: Verify failing pack - Absolute
    bv.verify_failed_pack('Absolute')

    # Case 10: Verify modified pack - Grafana
    bv.verify_modified_pack('Grafana', items_dict.get('Grafana'))

    # verify path modification
    if 'v2' in gcp.storage_bucket.name:
        bv.verify_modified_path('ModelingRule', 'AlibabaActionTrail', os.path.join('AlibabaActionTrail',
                                                                                   'ModelingRule', 'Alibaba.yml'))
        bv.verify_modified_path('ModelingRule', 'AlibabaActionTrail', os.path.join('AlibabaActionTrail',
                                                                                   'ModelingRule', 'Alibaba.jsom'))
        bv.verify_modified_path('ModelingRule', 'AlibabaActionTrail', os.path.join('AlibabaActionTrail',
                                                                                   'ModelingRule', 'Alibaba.xif'))

    is_valid = 'valid' if bv.is_valid else 'not valid'
    logging.info(f'The bucket {gcp.storage_bucket.name}/{gcp.storage_base_path} was found as {is_valid}')

    if not bv.is_valid:
        sys.exit(1)
