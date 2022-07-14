import argparse
import shutil
from git import GitCommandError, Repo, Head
from pathlib import Path
import subprocess
import json

changed_packs = set()


def add_changed_pack(func):
    def wrapper(*args, **kwargs):
        global changed_packs
        print(f'Running {func.__name__}', end=" ")
        res = func(*args, **kwargs)
        changed_packs.add(res)
        print("Done\n")

        return res
    return wrapper


@add_changed_pack
def create_new_pack():
    """
        Creates new pack with given pack name
    """
    content_path = Path(__file__).parent.parent.parent
    source_path = Path(__file__).parent / 'TestUploadFlow'
    dest_path = content_path / 'Packs' / 'TestUploadFlow'
    if dest_path.exists():
        shutil.rmtree(dest_path)
    shutil.copytree(source_path, dest_path)
    subprocess.call(['demisto-sdk', 'format', '-y', '-i', dest_path], stdout=subprocess.DEVNULL)
    return dest_path


@add_changed_pack
def add_dependency(base_pack: Path, new_depndency_pack: Path):
    metadata_json = base_pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    new_pack_name = new_depndency_pack.name
    base_metadata['dependencies'][new_pack_name] = {
        "mandatory": True,
        "display_name": new_pack_name
    }

    with metadata_json.open('w') as f:
        json.dump(base_metadata, f)
    subprocess.call(['demisto-sdk', 'update-release-notes', '-i',
                    f'{base_pack}', "--force", '--text', 'Adding release notes to check the upload flow'], stdout=subprocess.DEVNULL)

    return base_pack


@add_changed_pack
def enhance_release_notes(pack: Path):
    subprocess.call(['demisto-sdk', 'update-release-notes', '-i',
                    f'{pack}', "--force", '--text', 'Adding release notes to check the upload flow'], stdout=subprocess.DEVNULL)
    return pack


@add_changed_pack
def change_image(pack: Path):
    new_image = Path(__file__).parent / 'TestUploadFlow' / 'Integrations' / 'TestUploadFlow' / 'TestUploadFlow_image.png'
    for p in Path(pack).glob('**/*.png'):
        # shutil.rmtree(p)
        shutil.copy(new_image, p)
    return pack


@add_changed_pack
def update_existing_release_notes(pack: Path, relese_note: str):
    path = pack / 'ReleaseNotes' / relese_note
    if not path.exists():
        raise Exception("path is not valid release note")

    with path.open('a') as f:
        f.write('\n#### Upload flow\n - Test\n')
    return pack


@add_changed_pack
def set_pack_hidden(pack: Path):
    metadata_json = pack / 'pack_metadata.json'
    with metadata_json.open('r') as f:
        base_metadata = json.load(f)
    base_metadata['hidden'] = True
    with metadata_json.open('w') as f:
        json.dump(base_metadata, f)
    return pack


@add_changed_pack
def update_readme(pack: Path):
    for path in pack.glob('**/*.README.md'):
        with path.open('a') as f:
            f.write("\n#### Upload flow\n - Test\n")
    return pack


@add_changed_pack
def update_pack_ignore(pack: Path):
    pack_ignore = pack / ".pack-ignore"
    with pack_ignore.open('a') as f:
        f.write("\n[file:1_0_1.md]\nignore=RM104\n")
    return pack


def add_pack_to_landing_page(pack_name: str):
    global changed_packs
    content_path = Path(__file__).parent.parent.parent
    landing_page = content_path / 'Tests' / 'Marketplace' / 'landingPage_sections.json'
    with landing_page.open('r') as f:
        landing_json = json.load(f)
    landing_json['Getting Started'].append(pack_name)
    landing_json['Featured'].append(pack_name)
    with landing_page.open('w') as f:
        json.dump(landing_json, f)
    changed_packs.add(landing_page.parent)


@add_changed_pack
def add_1_0_0_release_notes(pack: Path):
    release_note = pack / 'ReleaseNotes' / '1_0_0.md'
    release_note.write_text(f"""
#### Integrations
##### {pack.name}
first release note
""")
    return pack


def create_new_branch(repo: Repo, new_branch_name: str) -> Head:
    branch = repo.create_head(new_branch_name)
    branch.checkout()
    print(f"Created new branch {repo.active_branch}")
    return branch


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", nargs="?", help="Content directory path, default is current directory.", default='.')
    parser.add_argument("-cb", "--content-branch", nargs="?",
                        help="The content branch name, if empty will run on current branch.")
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_arguments()
    repo = Repo(args.path)
    if args.content_branch:
        original_branch = args.content_branch
        repo.git.checkout(original_branch)
    else:
        original_branch = repo.active_branch
    try:
        new_branch_name = f"{original_branch}_upload_test_branch_{repo.active_branch.object.hexsha}"
        content_path = Path(__file__).parent.parent.parent
        packs_path = content_path / 'Packs'
        branch = create_new_branch(repo, new_branch_name)

        new_pack_path = create_new_pack()
        add_dependency(packs_path / 'Armis', new_pack_path)
        enhance_release_notes(packs_path / 'ZeroFox')
        change_image(packs_path / 'Armis')

        update_existing_release_notes(packs_path / 'Box', "2_1_2.md")
        enhance_release_notes(packs_path / 'Box')
        update_existing_release_notes(packs_path / 'Base', "1_13_13.md")
        add_1_0_0_release_notes(packs_path / 'BPA')
        set_pack_hidden(packs_path / 'Microsoft365Defender')
        update_readme(packs_path / 'Maltiverse')
        update_pack_ignore(packs_path / 'MISP')

        add_pack_to_landing_page('Trello')

        for p in changed_packs:
            repo.git.add(f"{p}/*")

        repo.git.commit(m="Added Test file")
        repo.git.push('--set-upstream', 'https://code.pan.run/xsoar/content.git', branch)  # disable-secrets-detection

    except GitCommandError as e:
        print(e)

    finally:
        repo.git.checkout(original_branch)
        if branch:
            repo.delete_head(branch, force=True)
