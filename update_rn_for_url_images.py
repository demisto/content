import subprocess
import os

PATH = "/Users/ipolishuk/dev/demisto/content/Packs"


def get_all_packs():
    return [pack for pack in os.listdir(PATH)]


def get_packs_with_binary_files_folders(packs: list) -> list:
    packs_with_binary_files_folder = []
    for pack in packs:
        if os.path.exists(f'{PATH}/{pack}/binary_files'):
            packs_with_binary_files_folder.append(pack)
    return packs_with_binary_files_folder


def update_rn(packs: list) -> None:
    for pack in packs:
        cmd = [
            'demisto-sdk',
            'update-release-notes',
            '-i',
            f'{PATH}/{pack}',
            '-f',
            '--text',
            'Documentation and metadata improvements.'
        ]
        subprocess.run(
            cmd
        )


def main():
    packs = get_all_packs()
    packs = get_packs_with_binary_files_folders(packs)
    update_rn(packs)


main()
