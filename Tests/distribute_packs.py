from subprocess import Popen, PIPE
from Tests.test_utils import run_command


class PacksManager:
    PACKS_ROOT_FOLDER = "Packs"

    def __init__(self, last_commit_hash, packs_artifacts):
        self.last_commit_hash = last_commit_hash
        self.packs_artifacts = packs_artifacts

    def get_modified_packs(self):
        cmd = F"git diff --name-only {self.last_commit_hash}...master | grep '{self.PACKS_ROOT_FOLDER}/'"
        modified_packs_path = run_command(cmd, use_shell=True).splitlines()

        return [p.split('/')[1] for p in modified_packs_path]

    def distribute_content_packs(self):
        modified_packs = self.get_modified_packs()


def main():
    last_commit_hash = "b05ea6fdd8b7e049d37e3d57657dc82efb7fb35"
    packs_artifacts = "some_artifacts"

    packs_manager = PacksManager(last_commit_hash=last_commit_hash,
                                 packs_artifacts=packs_artifacts)
    packs_manager.distribute_content_packs()


if __name__ == '__main__':
    main()
