from Tests.test_utils import run_command


class PacksManager:
    PACKS_ROOT_FOLDER = "Packs"

    def __init__(self, packs_artifacts):
        self.packs_artifacts = packs_artifacts

    def get_modified_packs_names(self):
        cmd = F"git diff --name-only HEAD..HEAD^ | grep '{self.PACKS_ROOT_FOLDER}/'"
        modified_packs_path = run_command(cmd, use_shell=True).splitlines()

        return [p.split('/')[1] for p in modified_packs_path]

    def distribute_content_packs(self):
        modified_packs_names = self.get_modified_packs_names()


def main():
    packs_artifacts = "some_artifacts"

    packs_manager = PacksManager(packs_artifacts=packs_artifacts)
    packs_manager.distribute_content_packs()


if __name__ == '__main__':
    main()
