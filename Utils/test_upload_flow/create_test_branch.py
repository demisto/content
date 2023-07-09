import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Union
from git import GitCommandError, Head, Repo
from zipfile import ZipFile
from packaging.version import Version

from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

versions_dict = {}
pack_items_dict = {}
changed_packs = set()


# HELPER FUNCTIONS


def json_write(file_path: str, data: Union[list, dict]):
    """ Writes given data to a json file

    Args:
        file_path: The file path
        data: The data to write

    """
    with open(file_path, "w") as f:
        f.write(json.dumps(data, indent=4))


def get_pack_content_paths(pack_path: Path, marketplace='xsoar'):
    """
    Gets a dict of all the paths of the given pack content items as it is in the bucket.
    To get these paths we are running the `demisto-sdk prepare-content` command and saving the result
    paths for each created item in the pack into a dict that will be saved in a file result `packs_items.json`.

    Args:
        pack_path (Path): The pack path.

    Returns:
        dict: The content items paths dict.
    """
    create_artifacts_command = ['demisto-sdk', 'prepare-content', '-i', f'Packs/{pack_path.name}', '-o', '.']
    if marketplace != 'xsoar':
        create_artifacts_command.extend(['-mp', f'{marketplace}'])

    try:
        logging.debug(f"Running the SDK prepare-content command for pack {pack_path.name} - "
                      f"Command: `{' '.join(create_artifacts_command)}`")
        res = subprocess.run(create_artifacts_command, capture_output=True, check=True)
        logging.debug(f"Result from prepare-content - stdout: [{str(res.stdout)}] stderr: [{str(res.stderr)}]")
    except subprocess.CalledProcessError as se:
        logging.error(f'Subprocess exception: {se}. stderr: [{se.stderr}] stdout: [{se.stdout}]')
        raise

    pack_artifacts_path = f'./{pack_path.name}'
    with ZipFile(f'{pack_path.name}.zip') as pack_artifacts_zip:
        pack_artifacts_zip.extractall(pack_artifacts_path)
    os.remove(f'{pack_path.name}.zip')

    content_dict = {}
    sub_dirs = os.listdir(pack_artifacts_path)
    sub_dirs = [str(sub_dir) for sub_dir in sub_dirs if '.' not in str(sub_dir)]

    for content_item_type in sub_dirs:
        if content_item_type not in ['ReleaseNotes', 'TestPlaybooks']:
            content_dict[content_item_type] = ['/'.join(p.parts[1:]) for p in Path(os.path.join(str(pack_artifacts_path),
                                                                                                content_item_type)).glob('*')]
    shutil.rmtree(pack_artifacts_path)
    return content_dict


def modify_item_path(item: Path, new_name: str):
    """
    Modify item's path, in order to verify that the pack was uploaded again
    """
    parent = item.parent
    item.rename(parent.joinpath(new_name))


def get_current_version(pack: Path):
    """
    Returns the current version of a pack
    """
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    return base_metadata['currentVersion']


def create_new_branch(repo: Repo, new_branch_name: str) -> Head:
    """
    Creates a new branch in a given repository
    """
    branch = repo.create_head(new_branch_name)
    branch.checkout()
    logging.info(f"Created new branch {repo.active_branch}")
    return branch


# TEST CHANGES FUNCTIONS


def add_changed_pack(func):
    def wrapper(*args, **kwargs):
        global changed_packs
        global versions_dict
        global pack_items_dict
        logging.info(f'Running {func.__name__}')
        pack, version, pack_items = func(*args, **kwargs)
        changed_packs.add(pack)
        versions_dict[str(pack.name)] = version
        if pack_items:
            pack_items_dict[str(pack.name)] = pack_items
        logging.info(f"Done running {func.__name__} on pack {pack.name}")

        return pack, version, pack_items
    return wrapper


@add_changed_pack
def create_new_pack():
    """
    Creates a new pack with a given pack name
    """
    content_path = Path(__file__).parent.parent.parent
    source_path = Path(__file__).parent / 'TestUploadFlow'
    dest_path = content_path / 'Packs' / 'TestUploadFlow'
    if dest_path.exists():
        shutil.rmtree(dest_path)
    shutil.copytree(source_path, dest_path)

    return dest_path, '1.0.0', get_pack_content_paths(dest_path)


@add_changed_pack
def add_dependency(base_pack: Path, new_depndency_pack: Path, mandatory: bool = True):
    """
    Adds a new dependency to a given pack
    """
    metadata_json = base_pack / 'pack_metadata.json'
    with metadata_json.open('r') as fr:
        base_metadata = json.load(fr)
    new_pack_name = new_depndency_pack.name
    base_metadata.setdefault('dependencies', {}).update({
        new_pack_name: {
            "mandatory": mandatory,
            "display_name": new_pack_name
        }
    })
    json_write(str(metadata_json), base_metadata)
    return base_pack, base_metadata['currentVersion'], None


@add_changed_pack
def enhance_release_notes(pack: Path):
    """
    Bumping a new version for a given pack with release notes
    """
    subprocess.call(['demisto-sdk', 'update-release-notes', '-i',
                    f'{pack}', "--force", '--text', 'testing adding new RN'], stdout=subprocess.DEVNULL)
    return pack, get_current_version(pack), None


@add_changed_pack
def change_image(pack: Path):
    """
    Changes an existing image of a given pack
    """
    new_image = pack.parent / 'TestUploadFlow' / 'Integrations' / 'TestUploadFlow' / 'TestUploadFlow_image.png'
    for p in Path(pack).glob('**/*.png'):
        shutil.copy(new_image, p)
    return pack, get_current_version(pack), None


@add_changed_pack
def update_existing_release_notes(pack: Path):
    """
    Modifies an existing pack release notes
    """
    latest_pack_version = str(max([Version(file_name.name.replace('.md', '').replace('_', '.'))
                                   for file_name in (pack / 'ReleaseNotes').glob('*_*_*.md')]))
    version_rn = latest_pack_version.replace('.', '_')
    path = pack / 'ReleaseNotes' / f'{version_rn}.md'
    if not path.exists():
        raise Exception("path is not valid release note")

    with path.open('w') as f:
        f.write('testing modifying existing RN')
    return pack, latest_pack_version, None


@add_changed_pack
def set_pack_hidden(pack: Path):
    """
    Sets a given pack to hidden
    """
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    base_metadata['hidden'] = True
    with metadata_json.open('w') as f:
        json.dump(base_metadata, f)
    return pack, base_metadata['currentVersion'], None


@add_changed_pack
def update_readme(pack: Path):
    """
    Updates a pack README file
    """
    for path in pack.glob('**/*README.md'):
        with path.open('a') as f:
            f.write("readme test upload flow")
    return pack, get_current_version(pack), None


@add_changed_pack
def create_failing_pack(pack: Path):
    """
    Modify a pack such that the upload fails on it - bumping the pack version
    without adding release notes.
    """
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    splited_pack_version = base_metadata['currentVersion'].rsplit('.', 1)
    base_metadata['currentVersion'] = '.'.join([splited_pack_version[0], str(int(splited_pack_version[1]) + 1)])
    json_write(str(metadata_json), base_metadata)
    return pack, base_metadata['currentVersion'], None


@add_changed_pack
def modify_pack(pack: Path, integration: str):
    """
    Modify a pack regularly, in order to check if all packs items are uploaded correctly
    """
    integration = pack / integration
    with integration.open('a') as f:
        f.write('\n#  CHANGE IN PACK')

    enhance_release_notes(pack)
    return pack, get_current_version(pack), get_pack_content_paths(pack)


@add_changed_pack
def modify_modeling_rules_path(modeling_rule: Path, old_name: str, new_name: str):
    """
    Modify modeling rules path, in order to verify that the pack was uploaded correctly and that the path was changed
    """
    modify_item_path(modeling_rule / f'{old_name}.xif', f'{new_name}.xif')
    modify_item_path(modeling_rule / f'{old_name}.yml', f'{new_name}.yml')
    modify_item_path(modeling_rule / f'{old_name}_schema.json', f'{new_name}_schema.json')
    parent = modeling_rule.parent
    pack_path = modeling_rule.parent.parent
    modeling_rule.rename(parent.joinpath(new_name))
    return pack_path, get_current_version(pack_path), get_pack_content_paths(pack_path, marketplace='marketplacev2')


@add_changed_pack
def modify_script_path(script: Path, old_name: str, new_name: str):
    """
    Modify script path, in order to verify that the pack was uploaded correctly and that the path was changed
    """
    modify_item_path(script / f'{old_name}.py', f'{new_name}.py')
    modify_item_path(script / f'{old_name}.yml', f'{new_name}.yml')
    modify_item_path(script / f'{old_name}_test.py', f'{new_name}_test.py')
    parent = script.parent
    pack_path = script.parent.parent
    script.rename(parent.joinpath(new_name))
    return pack_path, get_current_version(pack_path), get_pack_content_paths(pack_path)


def do_changes_on_branch(packs_path: Path):
    """
    Makes the test changes on the created branch
    """
    # Case 1: Verify new pack - TestUploadFlow
    new_pack_path, _, _ = create_new_pack()

    # Case 2: Verify modified pack - Armorblox
    modify_pack(packs_path / 'Armorblox', 'Integrations/Armorblox/Armorblox.py')

    # Case 3: Verify dependencies handling - Armis
    add_dependency(packs_path / 'Armis', new_pack_path)

    # Case 4: Verify new version - ZeroFox
    enhance_release_notes(packs_path / 'ZeroFox')

    # Case 5: Verify modified existing release notes - Box
    update_existing_release_notes(packs_path / 'Box')

    # Case 6: Verify pack is set to hidden - Microsoft365Defender
    set_pack_hidden(packs_path / 'Microsoft365Defender')

    # TODO: fix after README changes are collected the pack to upload is fixed - CIAC-5369
    # Case 7: Verify changed readme - Maltiverse
    # update_readme(packs_path / 'Maltiverse')

    # TODO: need to cause this pack to fail in another way because the current way cause validation to fail
    # Case 8: Verify failing pack - Absolute
    # create_failing_pack(packs_path / 'Absolute')

    # Case 9: Verify changed image - Armis
    change_image(packs_path / 'Armis')

    # Case 10: Verify modified modeling rule path - AlibabaActionTrail
    modify_modeling_rules_path(packs_path / 'AlibabaActionTrail/ModelingRules/AlibabaModelingRules',
                               'AlibabaModelingRules', 'Alibaba')

    # Case 11: Verify script path - CortexXDR
    modify_script_path(packs_path / 'CortexXDR/Scripts/XDRSyncScript',
                       'XDRSyncScript', 'XDRSyncScript_new_name')

    # case 12: Verify setting hidden dependency does not add this dependency to the metadata - MicrosoftAdvancedThreatAnalytics
    add_dependency(packs_path / 'MicrosoftAdvancedThreatAnalytics', packs_path / 'Microsoft365Defender',
                   mandatory=False)

    logging.info("Finished making test changes on the branch")


# MAIN FUNCTION


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", nargs="?", help="Content directory path, default is current directory.", default='.')
    parser.add_argument("-cb", "--content-branch", nargs="?",
                        help="The content branch name, if empty will run on current branch.")
    parser.add_argument("-tb", "--test-branch", nargs="?",
                        help="The content test branch name to create and test on.")
    parser.add_argument("-a", "--artifacts_path", help="Path to store the script's output", default=".")
    parser.add_argument("-g", "--gitlab-mirror-token", help="Gitlab mirror token for pushing commits "
                                                            "directly to gitlab repo")
    return parser.parse_args()


def main():
    install_logging('create_test_branch.log', logger=logging)

    args = parse_arguments()
    repo = Repo(args.path)
    if args.content_branch:
        original_branch = args.content_branch
        repo.git.checkout(original_branch)
    else:
        original_branch = repo.active_branch

    try:
        new_branch_name = args.test_branch if args.test_branch else f"{original_branch}_upload_test_branch_{time.time()}"
        content_path = Path(__file__).parent.parent.parent
        packs_path = content_path / 'Packs'
        branch = create_new_branch(repo, new_branch_name)

        logging.info(f"Starts doing test changes on branch '{branch.name}'")
        do_changes_on_branch(packs_path)

        for p in changed_packs:
            repo.git.add(f"{p}/*")

        repo.git.commit(m="Added Test file", no_verify=True)
        repo.git.push('--set-upstream',
                      f'https://GITLAB_PUSH_TOKEN:{args.gitlab_mirror_token}@'  # disable-secrets-detection
                      f'code.pan.run/xsoar/content.git', branch, push_option="ci.skip")  # disable-secrets-detection
        logging.info("Successfuly pushing the branch to Gitlab content repo")

    except GitCommandError as e:
        logging.error(e)

    finally:
        repo.git.checkout(original_branch)
        json_write(os.path.join(args.artifacts_path, 'packs_items.json'), pack_items_dict)
        json_write(os.path.join(args.artifacts_path, 'versions_dict.json'), versions_dict)


if __name__ == "__main__":
    main()
