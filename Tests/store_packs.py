import json
import os
import sys
import argparse
import warnings
import shutil
import uuid
import google.auth
from google.cloud import storage
from distutils.util import strtobool
from distutils.version import LooseVersion
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from Tests.test_utils import run_command, print_error, print_warning, print_color, LOG_COLORS, \
    collect_pack_content_items, input_to_list

# global constants
GCP_SERVICE_ACCOUNT_VAR = "GOOGLE_APPLICATION_CREDENTIALS"
STORAGE_BASE_PATH = "content/packs"
CONTENT_PACKS_FOLDER = "Packs"
IGNORED_FILES = ['__init__.py']
IGNORED_PATHS = [os.path.join(CONTENT_PACKS_FOLDER, p) for p in IGNORED_FILES]  # Packs/__init__.py is ignored
# the format is defined in issue #19786, may change in the future
DIR_NAME_TO_CONTENT_TYPE = {
    "Classifiers": "classifier",
    "Dashboards": "dashboard",
    "IncidentFields": "incidentfield",
    "IncidentTypes": "incidenttype",
    "IndicatorFields": "reputation",
    "Integrations": "integration",
    "Layouts": "layout",
    "Playbooks": "playbook",
    "Reports": "report",
    "Scripts": "automation",
    "Widgets": "widget"
}


class Pack(object):
    """Class that manipulates and manages the upload of pack's artifact and metadata to cloud storage.

    Args:
        pack_name (str): Pack root folder name.
        pack_path (str): Full path to pack folder.

    Attributes:
        PACK_INITIAL_VERSION (str): pack initial version that will be used as default.
        DATE_FORMAT (str): date format of.
        CHANGELOG_JSON (str): changelog json full name, may be changed in the future.
        CHANGELOG_MD (str): changelog md full name.
        README (str): pack's readme file name.
        METADATA (str): pack's metadata file name, the one that will be deployed to cloud storage.
        USER_METADATA (str); user metadata file name, the one that located in content repo.
        INDEX_NAME (str): pack's index name, may be changed in the future.

    """
    PACK_INITIAL_VERSION = "1.0.0"
    DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
    CHANGELOG_JSON = "changelog.json"
    CHANGELOG_MD = "changelog.md"
    README = "README.md"
    USER_METADATA = "pack_metadata.json"
    METADATA = "metadata.json"
    INDEX_NAME = "index"
    EXCLUDE_DIRECTORIES = ["TestPlaybooks"]

    def __init__(self, pack_name, pack_path):
        self._pack_name = pack_name
        self._pack_path = pack_path

    @property
    def name(self):
        """str: pack root folder name.
        """
        return self._pack_name

    @property
    def path(self):
        """str: pack folder full path.
        """
        return self._pack_path

    @property
    def latest_version(self):
        """str: Pack latest version from sorted keys of changelog.json file.
        """
        return self._get_latest_version()

    def _get_latest_version(self):
        """Return latest semantic version of the pack.

        In case that changelog.json file was not found, default value of 1.0.0 will be returned.
        Otherwise, keys of semantic pack versions will be collected and sorted in descending and return latest version.
        For additional information regarding changelog.json format go to issue #19786

        Returns:
            str: Pack latest version.

        """
        changelog_path = os.path.join(self._pack_path, Pack.CHANGELOG_JSON)

        if not os.path.exists(changelog_path):
            return self.PACK_INITIAL_VERSION

        with open(changelog_path, "r") as changelog_file:
            changelog = json.load(changelog_file)
            pack_versions = [LooseVersion(v) for v in changelog.keys()]
            pack_versions.sort(reverse=True)

            return pack_versions[0].vstring

    @staticmethod
    def _parse_pack_metadata(user_metadata, pack_content_items, pack_id):
        """Parses pack metadata according to issue #19786 and #20091. Part of field may change over the time.

        Args:
            user_metadata (dict): user metadata that was created in pack initialization.
            pack_content_items (dict): content items located inside specific pack.
            pack_id (str): pack unique identifier.

        Returns:
            dict: parsed pack metadata.

        """
        pack_metadata = {}
        # part of old packs are initialized with empty list
        user_metadata = {} if isinstance(user_metadata, list) else user_metadata
        pack_metadata['name'] = user_metadata.get('name', '')
        pack_metadata['id'] = pack_id
        pack_metadata['description'] = user_metadata.get('description', '')
        pack_metadata['created'] = user_metadata.get('created', datetime.utcnow().strftime(Pack.DATE_FORMAT))
        pack_metadata['updated'] = datetime.utcnow().strftime(Pack.DATE_FORMAT)
        pack_metadata['support'] = user_metadata.get('support', '')
        pack_metadata['supportDetails'] = {}
        support_url = user_metadata.get('url')
        if support_url:
            pack_metadata['supportDetails']['url'] = support_url

        support_email = user_metadata.get('email')
        if support_email:
            pack_metadata['supportDetails']['email'] = support_email
        pack_metadata['author'] = user_metadata.get('author', '')
        # todo get vendor image and upload to storage
        pack_metadata['authorImage'] = ''
        is_beta = user_metadata.get('beta', False)
        pack_metadata['beta'] = bool(strtobool(is_beta)) if isinstance(is_beta, str) else is_beta
        is_deprecated = user_metadata.get('deprecated', False)
        pack_metadata['deprecated'] = bool(strtobool(is_beta)) if isinstance(is_deprecated, str) else is_deprecated
        pack_metadata['certification'] = user_metadata.get('certification', '')
        pack_metadata['price'] = int(user_metadata.get('price', 0))
        pack_metadata['serverMinVersion'] = user_metadata.get('serverMinVersion', '')
        pack_metadata['serverLicense'] = user_metadata.get('serverLicense', '')
        pack_metadata['currentVersion'] = user_metadata.get('currentVersion', '')
        # todo check if this field is necessary
        pack_metadata['general'] = input_to_list(user_metadata.get('general'))
        pack_metadata['tags'] = input_to_list(user_metadata.get('tags'))
        pack_metadata['categories'] = input_to_list(user_metadata.get('categories'))
        pack_metadata['contentItems'] = {DIR_NAME_TO_CONTENT_TYPE[k]: v for (k, v) in pack_content_items.items()
                                         if k in DIR_NAME_TO_CONTENT_TYPE and v}
        # todo collect all integrations display name
        pack_metadata["integrations"] = []
        pack_metadata["useCases"] = input_to_list(user_metadata.get('useCases'))
        pack_metadata["keywords"] = input_to_list(user_metadata.get('keywords'))
        pack_metadata["dependencies"] = {}  # TODO: build dependencies tree

        return pack_metadata

    def zip_pack(self):
        """Zips pack folder and excludes not wanted directories.

        Returns:
            str: full path to created pack zip.

        """
        zip_pack_path = f"{self._pack_path}.zip"

        with ZipFile(zip_pack_path, 'w', ZIP_DEFLATED) as pack_zip:
            for root, dirs, files in os.walk(self._pack_path, topdown=True):
                dirs[:] = [d for d in dirs if d not in Pack.EXCLUDE_DIRECTORIES]

                for f in files:
                    full_file_path = os.path.join(root, f)
                    relative_file_path = os.path.relpath(full_file_path, self._pack_path)
                    pack_zip.write(filename=full_file_path, arcname=relative_file_path)

        print_color(f"Finished zipping {self._pack_name} pack.", LOG_COLORS.GREEN)

        return zip_pack_path

    def upload_to_storage(self, zip_pack_path, latest_version, storage_bucket, override_pack):
        """ Manages the upload of pack zip artifact to correct path in cloud storage.
        The zip pack will be uploaded to following path: /content/packs/pack_name/pack_latest_version.
        In case that zip pack artifact already exist at constructed path, the upload will be skipped.

        Args:
            zip_pack_path (str): full path to pack zip artifact.
            latest_version (str): pack latest version.
            storage_bucket (google.cloud.storage.bucket.Bucket): google cloud storage bucket.
            override_pack (bool): whether to override existing pack.

        Returns:
            bool: True is pack was successfully uploaded. False in case that packs already exists at the bucket.

        """
        version_pack_path = os.path.join(STORAGE_BASE_PATH, self._pack_name, latest_version)
        existing_files = [f.name for f in storage_bucket.list_blobs(prefix=version_pack_path)]

        if existing_files and not override_pack:
            print_warning(f"The following packs already exist at storage: {', '.join(existing_files)}")
            print_warning(f"Skipping step of uploading {self._pack_name}.zip to storage.")
            return False

        pack_full_path = f"{version_pack_path}/{self._pack_name}.zip"
        blob = storage_bucket.blob(pack_full_path)

        with open(zip_pack_path, "rb") as pack_zip:
            blob.upload_from_file(pack_zip)
        print_color(f"Uploaded {self._pack_name} pack to {pack_full_path} path.", LOG_COLORS.GREEN)

        return True

    def format_metadata(self, pack_content_items):
        """Re-formats metadata according to marketplace metadata format defined in issue #19786 and writes back
        the result.

        Args:
            pack_content_items (dict): content items that are located inside specific pack. Possible keys of the dict:
            Classifiers, Dashboards, IncidentFields, IncidentTypes, IndicatorFields, Integrations, Layouts, Playbooks,
            Reports, Scripts and Widgets. Each key is mapped to list of items with name and description. Several items
            have no description.

        """
        user_metadata_path = os.path.join(self._pack_path, Pack.USER_METADATA)  # user metadata path before parsing
        metadata_path = os.path.join(self._pack_path, Pack.METADATA)  # deployed metadata path after parsing

        if not os.path.exists(user_metadata_path):
            print_error(f"{self._pack_name} pack is missing {Pack.USER_METADATA} file.")
            sys.exit(1)

        with open(user_metadata_path, "r") as user_metadata_file:
            user_metadata = json.load(user_metadata_file)  # loading user metadata
            formatted_metadata = Pack._parse_pack_metadata(user_metadata=user_metadata,
                                                           pack_content_items=pack_content_items,
                                                           pack_id=self._pack_name)

        with open(metadata_path, "w") as metadata_file:
            json.dump(formatted_metadata, metadata_file, indent=4)  # writing back parsed metadata

        print_color(f"Finished formatting {self._pack_name} packs's {Pack.METADATA} {metadata_path} file.",
                    LOG_COLORS.GREEN)

    def parse_release_notes(self):
        """Need to implement the changelog.md parsing and changelog.json creation after design is finalized.

        """
        changelog_md_path = os.path.join(self._pack_path, Pack.CHANGELOG_MD)

        if not os.path.exists(changelog_md_path):
            print_error(f"The pack {self._pack_name} is missing {Pack.CHANGELOG_MD} file.")
            sys.exit(1)

        # with open(changelog_md_path, 'r') as release_notes_file:
        #     release_notes = release_notes_file.read()
        # todo implement release notes logic and create changelog.json

        return {}

    def prepare_for_index_upload(self):
        """Removes and leaves only necessary files in pack folder.

        """
        files_to_leave = [Pack.METADATA, Pack.CHANGELOG_JSON, Pack.README]

        for file_or_folder in os.listdir(self._pack_path):
            files_or_folder_path = os.path.join(self._pack_path, file_or_folder)

            if file_or_folder in files_to_leave:
                continue

            if os.path.isdir(files_or_folder_path):
                shutil.rmtree(files_or_folder_path)
            else:
                os.remove(files_or_folder_path)

    def cleanup(self):
        """Finalization action, removes extracted pack folder.

        """
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path)
            print(f"Cleanup {self._pack_name} pack from: {self._pack_path}")


def get_modified_packs(specific_packs=""):
    """Detects and returns modified or new packs names.

    Checks the git difference between two commits, current and previous and greps only ones with prefix Packs/.
    After content repo will move only for Packs structure, the grep pipe can be removed.
    In case of local dev mode, the function will receive comma separated list of target packs.

    Args:
        specific_packs (str): comma separated packs names or `All` for all available packs in content.

    Returns:
        set: unique collection of modified/new packs names.

    """
    if specific_packs.lower() == "all":
        content_root_path = os.path.abspath(os.path.join(__file__, '../..'))
        content_packs_path = os.path.join(content_root_path, CONTENT_PACKS_FOLDER)

        if os.path.exists(content_packs_path):
            all_packs = {p for p in os.listdir(content_packs_path) if p not in IGNORED_FILES}
            print(f"Number of selected packs is: {len(all_packs)}")
            return all_packs
        else:
            print(f"Folder {CONTENT_PACKS_FOLDER} was not found at the following path: {content_packs_path}")
            sys.exit(1)

    elif specific_packs:
        modified_packs = {p.strip() for p in specific_packs.split(',')}
        print(f"Number of selected packs is: {len(modified_packs)}")
        return modified_packs
    else:
        cmd = f"git diff --name-only HEAD..HEAD^ | grep 'Packs/'"
        modified_packs_path = run_command(cmd, use_shell=True).splitlines()
        modified_packs = {p.split('/')[1] for p in modified_packs_path if p not in IGNORED_PATHS}
        print(f"Number of modified packs is: {len(modified_packs)}")

        return modified_packs


def extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path):
    """Extracts changed packs from content pack artifact zip.

    Args:
        modified_packs (set): collection of modified/new packs.
        packs_artifacts_path (str): full path to content artifacts zip file.
        extract_destination_path (str): full path to directory where to extract the packs.

    """
    print("Starting extracting modified pack:")
    with ZipFile(packs_artifacts_path) as packs_artifacts:
        for pack in packs_artifacts.namelist():
            for modified_pack in modified_packs:

                if pack.startswith(f"{modified_pack}/"):
                    packs_artifacts.extract(pack, extract_destination_path)
                    print(f"Extracted {pack} to path: {extract_destination_path}")
    print_color("Finished extracting modified packs", LOG_COLORS.GREEN)


def init_storage_client():
    """Initialize google cloud storage client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Return:
        storage.Client: initialized google cloud storage client.
    """
    if os.environ.get(GCP_SERVICE_ACCOUNT_VAR):
        print_color("Initialized gcp service account", LOG_COLORS.GREEN)
        return storage.Client()
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        print_color("Initialized gcp personal account", LOG_COLORS.GREEN)
        return storage.Client(credentials=credentials, project=project)


def download_and_extract_index(storage_bucket, extract_destination_path):
    """Downloads and extracts index zip from cloud storage.

    Args:
        storage_bucket (google.cloud.storage.bucket.Bucket): google storage bucket where index.zip is stored.
        extract_destination_path (str): the full path of extract folder.

    Returns:
        str: extracted index folder full path.
        Blob: google cloud storage object that represents index.zip blob.

    """
    index_storage_path = os.path.join(STORAGE_BASE_PATH, f"{Pack.INDEX_NAME}.zip")
    download_index_path = os.path.join(extract_destination_path, f"{Pack.INDEX_NAME}.zip")

    index_blob = storage_bucket.blob(index_storage_path)
    index_folder_path = os.path.join(extract_destination_path, Pack.INDEX_NAME)

    if not index_blob.exists():
        os.mkdir(index_folder_path)
        return index_folder_path, index_blob

    index_blob.cache_control = "no-cache"  # index zip should never be cached in the memory, should be updated version
    index_blob.reload()
    index_blob.download_to_filename(download_index_path)

    if os.path.exists(download_index_path):
        with ZipFile(download_index_path, 'r') as index_zip:
            index_zip.extractall(extract_destination_path)

        # index_folder_path = os.path.join(extract_destination_path, Pack.INDEX_NAME)

        if not os.path.exists(index_folder_path):
            print_error(f"Failed creating {Pack.INDEX_NAME} folder with extracted data.")
            sys.exit(1)

        os.remove(download_index_path)
        print_color(f"Finished downloading and extracting {Pack.INDEX_NAME} file to {extract_destination_path}",
                    LOG_COLORS.GREEN)

        return index_folder_path, index_blob
    else:
        print_error(f"Failed to download {Pack.INDEX_NAME}.zip file from cloud storage.")
        sys.exit(1)


def update_index_folder(index_folder_path, pack_name, pack_path):
    """Copies pack folder into index folder.

    Args:
        index_folder_path (str): full path to index folder.
        pack_name (str): pack folder name to copy.
        pack_path (str): pack folder full path.

    """
    index_folder_subdirectories = [d for d in os.listdir(index_folder_path) if
                                   os.path.isdir(os.path.join(index_folder_path, d))]
    index_pack_path = os.path.join(index_folder_path, pack_name)

    if pack_name in index_folder_subdirectories:
        shutil.rmtree(index_pack_path)
    shutil.copytree(pack_path, index_pack_path)


def upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number):
    """Upload updated index zip to cloud storage.

    Args:
        index_folder_path (str): index folder full path.
        extract_destination_path (str): extract folder full path.
        index_blob (Blob): google cloud storage object that represents index.zip blob.
        build_number (str): circleCI build number, used as an index revision.

    """
    with open(os.path.join(index_folder_path, f"{Pack.INDEX_NAME}.json"), "w+") as index_file:
        index = {
            'description': 'Master index for Demisto Content Packages',
            'baseUrl': 'https://marketplace.demisto.ninja/content/packs',  # disable-secrets-detection
            'revision': build_number,
            'modified': datetime.utcnow().strftime(Pack.DATE_FORMAT),
            'landingPage': {
                'sections': [
                    'Trending',
                    'Recommended by Demisto',
                    'New',
                    'Getting Started'
                ]
            }
        }
        json.dump(index, index_file, indent=4)

    index_zip_name = os.path.basename(index_folder_path)
    index_zip_path = shutil.make_archive(base_name=index_folder_path, format="zip",
                                         root_dir=extract_destination_path, base_dir=index_zip_name)

    index_blob.cache_control = "no-cache"  # disabling caching for index blob
    if index_blob.exists():
        index_blob.reload()

    index_blob.upload_from_filename(index_zip_path)
    shutil.rmtree(index_folder_path)
    print_color(f"Finished uploading {Pack.INDEX_NAME}.zip to storage.", LOG_COLORS.GREEN)


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Store packs in cloud storage.")
    # disable-secrets-detection-start
    parser.add_argument('-a', '--artifacts_path', help="The full path of packs artifacts", required=True)
    parser.add_argument('-e', '--extract_path', help="Full path of folder to extract wanted packs", required=True)
    parser.add_argument('-p', '--pack_names',
                        help=("Comma separated list of target pack names. "
                              "Define `All` in order to store all available packs."),
                        required=False, default="")
    parser.add_argument('-b', '--bucket_name', help="Storage bucket name", required=True)
    parser.add_argument('-n', '--ci_build_number',
                        help="CircleCi build number (will be used as hash revision at index file)", required=False)
    parser.add_argument('-o', '--override_pack', help="Override existing packs in cloud storage", default=False,
                        action='store_true', required=False)
    # disable-secrets-detection-end
    return parser.parse_args()


def main():
    # disable-secrets-detection-start
    """
    For local development use your personal account and authenticate using Google Cloud SDK by running:
    `gcloud auth application-default login`.
    For more information go to: https://googleapis.dev/python/google-api-core/latest/auth.html
    """
    # disable-secrets-detection-end
    option = option_handler()
    packs_artifacts_path = option.artifacts_path
    extract_destination_path = option.extract_path
    storage_bucket_name = option.bucket_name
    specific_packs = option.pack_names
    build_number = option.ci_build_number if option.ci_build_number else str(uuid.uuid4())
    override_pack = option.override_pack

    # detect new or modified packs
    modified_packs = get_modified_packs(specific_packs)
    extract_modified_packs(modified_packs, packs_artifacts_path, extract_destination_path)
    packs_list = [Pack(pack_name, os.path.join(extract_destination_path, pack_name)) for pack_name in modified_packs
                  if os.path.exists(os.path.join(extract_destination_path, pack_name))]

    # google cloud storage client initialized
    storage_client = init_storage_client()
    storage_bucket = storage_client.get_bucket(storage_bucket_name)
    index_folder_path, index_blob = download_and_extract_index(storage_bucket, extract_destination_path)
    index_was_updated = False  # indicates whether one or more index folders were updated

    for pack in packs_list:
        pack_content_items = collect_pack_content_items(pack.path)
        pack.format_metadata(pack_content_items)
        # todo finish implementation of release notes
        # pack.parse_release_notes()
        zip_pack_path = pack.zip_pack()
        uploaded_successfully = pack.upload_to_storage(zip_pack_path, pack.latest_version, storage_bucket,
                                                       override_pack)
        # in case that pack already exist at cloud storage path, skipped further steps
        if not uploaded_successfully:
            pack.cleanup()
            continue

        pack.prepare_for_index_upload()
        update_index_folder(index_folder_path=index_folder_path, pack_name=pack.name, pack_path=pack.path)
        index_was_updated = True  # detected index update
        pack.cleanup()

    if index_was_updated:
        upload_index_to_storage(index_folder_path, extract_destination_path, index_blob, build_number)
    else:
        print_warning(f"Skipping uploading index.zip to storage.")


if __name__ == '__main__':
    main()
