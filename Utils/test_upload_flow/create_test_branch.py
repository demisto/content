import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Union

from git import GitCommandError, Head, Repo

# from Tests.Marketplace.marketplace_services import *
versions_dict = {}
pack_items_dict = {}
changed_packs = set()

import logging

# from Tests.scripts.utils.log_util import install_logging
# install_logging('create_test_branch.log', logger=logging)


def json_write(file_path: str, data: Union[list, dict]):
    """ Writes given data to a json file

    Args:
        file_path: The file path
        data: The data to write

    """
    with open(file_path, "w") as f:
        f.write(json.dumps(data, indent=4))


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
        logging.info(f"Done running {func.__name__} on pack {pack}")

        return pack, version, pack_items
    return wrapper


@add_changed_pack
def create_new_pack():
    """
        Creates new pack with given pack name
        returns a dict with the created content items in the form of {item_type: item_path}
    """
    content_dict = {}
    content_path = Path(__file__).parent.parent.parent
    source_path = Path(__file__).parent / 'TestUploadFlow'
    dest_path = content_path / 'Packs' / 'TestUploadFlow'
    if dest_path.exists():
        shutil.rmtree(dest_path)
    shutil.copytree(source_path, dest_path)

    sub_dirs = os.listdir(source_path)
    sub_dirs = [str(sub_dir) for sub_dir in sub_dirs if '.' not in str(sub_dir)]
    prefix_dict = {content_item: content_item.lower()[:-1] for content_item in sub_dirs}
    prefix_dict['Layouts'] = 'layoutscontainer'
    prefix_dict['IndicatorTypes'] = 'reputation'

    for content_item in sub_dirs:
        if content_item in ['Integrations', 'Scripts']:
            content_dict[content_item] = os.path.join('TestUploadFlow', content_item, 'TestUploadFlow',
                                                      f'{prefix_dict[content_item]}-TestUploadFlow.yml')
        elif content_item not in ['ReleaseNotes', 'TestPlaybooks']:
            extension = 'yml' if content_item == 'Playbooks' else 'json'
            content_dict[content_item] = os.path.join('TestUploadFlow', content_item,
                                                      f'{prefix_dict[content_item]}-TestUploadFlow.{extension}')

    return dest_path, '1.0.0', content_dict


@add_changed_pack
def add_dependency(base_pack: Path, new_depndency_pack: Path):
    metadata_json = base_pack / 'pack_metadata.json'
    with metadata_json.open('r') as fr:
        base_metadata = json.load(fr)
    new_pack_name = new_depndency_pack.name
    base_metadata['dependencies'][new_pack_name] = {
        "mandatory": True,
        "display_name": new_pack_name
    }
    json_write(str(metadata_json), base_metadata)
    return base_pack, base_metadata['currentVersion'], None


@add_changed_pack
def enhance_release_notes(pack: Path):
    subprocess.call(['demisto-sdk', 'update-release-notes', '-i',
                    f'{pack}', "--force", '--text', 'testing adding new RN'], stdout=subprocess.DEVNULL)
    return pack, get_current_version(pack), None


@add_changed_pack
def change_image(pack: Path):
    new_image = Path(__file__).parent / 'TestUploadFlow' / 'Integrations' / 'TestUploadFlow' / 'TestUploadFlow_image.png'
    for p in Path(pack).glob('**/*.png'):
        shutil.copy(new_image, p)
    return pack, get_current_version(pack), None


@add_changed_pack
def update_existing_release_notes(pack: Path, version: str):
    version_rn = version.replace('.', '_')
    path = pack / 'ReleaseNotes' / f'{version_rn}.md'
    if not path.exists():
        raise Exception("path is not valid release note")

    with path.open('a') as f:
        f.write('testing modifying existing RN')
    return pack, version, None


@add_changed_pack
def set_pack_hidden(pack: Path):
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    base_metadata['hidden'] = True
    with metadata_json.open('w') as f:
        json.dump(base_metadata, f)
    return pack, base_metadata['currentVersion'], None


@add_changed_pack
def update_readme(pack: Path):
    for path in pack.glob('**/*README.md'):
        with path.open('a') as f:
            f.write("readme test upload flow")
    return pack, get_current_version(pack), None


@add_changed_pack
def update_pack_ignore(pack: Path):
    pack_ignore = pack / ".pack-ignore"
    with pack_ignore.open('a') as f:
        f.write("\n[file:1_0_1.md]\nignore=RM104\n")
    return pack, get_current_version(pack), None


@add_changed_pack
def create_failing_pack(integration: Path):
    """
    Modify a pack such that the upload fails on it - modifying a pack
    without adding release notes and without bumping the version.
    """
    with integration.open('a') as f:
        f.write('\n#  CHANGE IN PACK')
    return integration.parent.parent.parent, get_current_version(integration.parent.parent.parent), None


def modify_pack(pack: Path, integration: str):
    """
    Modify a pack regularly, in order to check if all packs items are uploaded correctly
    """
    integration = pack / integration
    with integration.open('a') as f:
        f.write('\n#  CHANGE IN PACK')
    enhance_release_notes(pack)
    items_dict = {}
    # TODO: here should add a section that collects all of the pack's content items, and returns it as a dict
    #  (same handling as in TestUploadFlow dummy pack, in create_new_pack
    return pack, get_current_version(pack), items_dict


@add_changed_pack
def modify_item_path(item: Path, new_name: str, pack_id: Path):
    """
    Modify item's path, in order to verify that the pack was uploaded again
    """
    parent = item.parent
    item.rename(parent.joinpath(new_name))
    return item.parent.parent.parent, get_current_version(pack_id), None


@add_changed_pack
def add_1_0_0_release_notes(pack: Path):
    release_note = pack / 'ReleaseNotes' / '1_0_0.md'
    release_note.write_text(f"""
#### Integrations
##### {pack.name}
first release note
""")
    return pack, get_current_version(pack), None


def get_current_version(pack: Path):
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    return base_metadata['currentVersion']


# def get_all_packs_items_dict(pack: Path):
#     pack = Pack(pack.name, str(pack))
#     pack.collect_content_items()
#     return pack._content_items


def create_new_branch(repo: Repo, new_branch_name: str) -> Head:
    branch = repo.create_head(new_branch_name)
    branch.checkout()
    logging.info(f"Created new branch {repo.active_branch}")
    return branch


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", nargs="?", help="Content directory path, default is current directory.", default='.')
    parser.add_argument("-cb", "--content-branch", nargs="?",
                        help="The content branch name, if empty will run on current branch.")
    parser.add_argument("-a", "--artifacts_path", help="Path to store the script's output", default=".")
    parser.add_argument("-g", "--gitlab-mirror-token", help="Gitlab mirror token for pushing commits "
                                                            "directly to gitlab repo")
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_arguments()
    repo = Repo(args.path)
    if args.content_branch:
        original_branch = args.content_branch
        repo.git.checkout(original_branch)
    else:
        original_branch = repo.active_branch
        pass
    try:
        new_branch_name = f"{original_branch}_upload_test_branch_{time.time()}"
        content_path = Path(__file__).parent.parent.parent
        packs_path = content_path / 'Packs'
        branch = create_new_branch(repo, new_branch_name)

        new_pack_path = create_new_pack()[0]
        add_dependency(packs_path / 'Armis', new_pack_path)
        enhance_release_notes(packs_path / 'ZeroFox')
        change_image(packs_path / 'Armis')

        update_existing_release_notes(packs_path / 'Box', "2.1.2")
        add_1_0_0_release_notes(packs_path / 'BPA')
        # set_pack_hidden(packs_path / 'Microsoft365Defender') TODO: fix after hidden pack mechanism is fixed
        update_readme(packs_path / 'Maltiverse')
        update_pack_ignore(packs_path / 'MISP')

        create_failing_pack(packs_path / 'Absolute/Integrations/Absolute/Absolute.py')
        modify_pack(packs_path / 'Grafana', 'Integrations/Grafana/Grafana.py')
        modify_item_path(packs_path / 'AlibabaActionTrail/ModelingRules/AlibabaModelingRules/AlibabaModelingRules.xif',
                         'Alibaba.xif', packs_path / 'AlibabaActionTrail')
        modify_item_path(packs_path / 'AlibabaActionTrail/ModelingRules/AlibabaModelingRules/AlibabaModelingRules.yml',
                         'Alibaba.yml', packs_path / 'AlibabaActionTrail')
        modify_item_path(packs_path /
                         'AlibabaActionTrail/ModelingRules/AlibabaModelingRules/AlibabaModelingRules_schema.json',
                         'Alibaba_schema.json', packs_path / 'AlibabaActionTrail') # TODO: add script

        for p in changed_packs:
            repo.git.add(f"{p}/*")

        repo.git.commit(m="Added Test file", no_verify=True)
        repo.git.push('--set-upstream',
                      f'https://GITLAB_PUSH_TOKEN:{args.gitlab_mirror_token}@'  # disable-secrets-detection
                      f'code.pan.run/xsoar/content.git', branch)  # disable-secrets-detection

    except GitCommandError as e:
        logging.error(e)

    finally:
        repo.git.checkout(original_branch)
        json_write(os.path.join(args.artifacts_path, 'packs_items.json'), pack_items_dict)
        json_write(os.path.join(args.artifacts_path, 'versions_dict.json'), versions_dict)

        print(new_branch_name)

