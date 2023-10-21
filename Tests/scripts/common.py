from pathlib import Path

CONTENT_NIGHTLY = 'Content Nightly'
CONTENT_PR = 'Content PR'
BUCKET_UPLOAD = 'Upload Packs to Marketplace Storage'
SDK_NIGHTLY = 'Demisto SDK Nightly'
PRIVATE_NIGHTLY = 'Private Nightly'
TEST_NATIVE_CANDIDATE = 'Test Native Candidate'
SECURITY_SCANS = 'Security Scans'
BUILD_MACHINES_CLEANUP = 'Build Machines Cleanup'
WORKFLOW_TYPES = {
    CONTENT_NIGHTLY,
    CONTENT_PR,
    SDK_NIGHTLY,
    BUCKET_UPLOAD,
    PRIVATE_NIGHTLY,
    TEST_NATIVE_CANDIDATE,
    SECURITY_SCANS,
    BUILD_MACHINES_CLEANUP
}


def get_instance_directories(artifacts_path: Path) -> dict[str, Path]:
    test_playbooks_result_files_list: dict[str, Path] = {}
    for directory in artifacts_path.iterdir():
        if directory.is_dir() and directory.name.startswith("instance_"):
            instance_role_txt = directory / "instance_role.txt"
            if instance_role_txt.exists():
                instance_role: str = instance_role_txt.read_text().replace("\n", "")
                test_playbooks_result_files_list[instance_role] = directory
    return test_playbooks_result_files_list
