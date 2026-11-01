from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from download_packs_and_docker_images import (
    PackInfo,
    extract_docker_images_from_pack_zips,
    get_pack_names,
    load_index_packs,
    should_filter_out_pack,
    zip_folder,
)

# ---------------------------------------------------------------------------
# File existence checks
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestFileExistence:
    """Verify that the script and test files exist on disk."""

    def test_script_file_exists(self):
        script_path = REPO_ROOT / "contribution" / "utils" / "download_packs_and_docker_images.py"
        assert script_path.is_file(), f"Expected script at {script_path}"

    def test_test_file_exists(self):
        test_path = REPO_ROOT / "contribution" / "Tests" / "test_download_packs_and_docker_images.py"
        assert test_path.is_file(), f"Expected test file at {test_path}"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

# Raw metadata used to build index.zip in tests (keyed by pack_id)
MOCK_RAW_METADATA: dict[str, dict] = {
    "mock_pack": {
        "id": "mock_pack",
        "name": "Mock Pack",
        "currentVersion": "1.2.3",
        "author": "Cortex XSOAR",
        "deprecated": False,
        "certification": "certified",
        "tags": ["Security"],
        "useCases": ["Phishing"],
        "categories": ["Data Enrichment & Threat Intelligence"],
        "marketplaces": ["xsoar", "marketplacev2"],
    },
    "mock_pack_2": {
        "id": "mock_pack_2",
        "name": "Mock Pack 2",
        "currentVersion": "2.0.0",
        "author": "Community",
        "deprecated": False,
    },
    "deprecated_pack": {
        "id": "deprecated_pack",
        "name": "Deprecated Pack",
        "currentVersion": "0.1.0",
        "author": "Cortex XSOAR",
        "deprecated": True,
    },
}

# Expected output of load_index_packs: display_name -> PackInfo
MOCK_INDEX_PACKS: dict[str, PackInfo] = {
    "Mock Pack": PackInfo(id="mock_pack", name="Mock Pack", current_version="1.2.3", author="Cortex XSOAR", deprecated=False),
    "Mock Pack 2": PackInfo(id="mock_pack_2", name="Mock Pack 2", current_version="2.0.0", author="Community", deprecated=False),
    "Deprecated Pack": PackInfo(
        id="deprecated_pack", name="Deprecated Pack", current_version="0.1.0", author="Cortex XSOAR", deprecated=True
    ),
}

PACK1_DATA_MOCK = {
    "name": "Pack1 (Deprecated)",
    "field": "value",
    "field2": "value2",
    "deprecated": True,
}

PACK2_DATA_MOCK = {
    "name": "Pack2",
    "field": "value",
    "field2": "value2",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_index_zip(raw_metadata: dict[str, dict]) -> bytes:
    """Build an in-memory index.zip matching the marketplace bucket layout.

    Args:
        raw_metadata: Mapping of pack_id -> raw metadata dict.

    Structure: index/<pack_id>/metadata.json
    """
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as z:
        for pack_id, metadata in raw_metadata.items():
            z.writestr(f"index/{pack_id}/metadata.json", json.dumps(metadata))
    return buf.getvalue()


def _build_pack_zip_with_yaml(yaml_content: str) -> bytes:
    """Build an in-memory pack zip containing a single YAML file."""
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as z:
        z.writestr("Integrations/MyIntegration/MyIntegration.yml", yaml_content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: load_index_packs
# ---------------------------------------------------------------------------


class TestLoadIndexPacks:
    """Tests for the load_index_packs function."""

    @patch("download_packs_and_docker_images.requests.request")
    def test_load_index_packs_success(self, mock_request: MagicMock) -> None:
        """
        Given:
            - A valid index.zip response from the marketplace bucket.
        When:
            - Calling load_index_packs with verify_ssl=True.
        Then:
            - Returns a dict mapping display_name -> PackInfo for each pack.
        """
        index_zip_bytes = _build_index_zip(MOCK_RAW_METADATA)
        mock_response = MagicMock()
        mock_response.content = index_zip_bytes
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        result = load_index_packs(verify_ssl=True)

        assert len(result) == 3
        assert "Mock Pack" in result
        assert result["Mock Pack"]["id"] == "mock_pack"
        assert result["Mock Pack"]["current_version"] == "1.2.3"
        assert result["Mock Pack"]["name"] == "Mock Pack"
        assert result["Deprecated Pack"]["deprecated"] is True
        assert result["Mock Pack 2"]["author"] == "Community"
        # Verify optional fields are populated when present in metadata
        assert result["Mock Pack"]["certification"] == "certified"
        assert result["Mock Pack"]["tags"] == ["Security"]
        assert result["Mock Pack"]["use_cases"] == ["Phishing"]
        assert result["Mock Pack"]["categories"] == ["Data Enrichment & Threat Intelligence"]
        assert result["Mock Pack"]["marketplaces"] == ["xsoar", "marketplacev2"]
        # Verify optional fields are absent when not in metadata
        assert "certification" not in result["Mock Pack 2"]
        assert "tags" not in result["Mock Pack 2"]
        assert "use_cases" not in result["Mock Pack 2"]

    @patch("download_packs_and_docker_images.requests.request")
    def test_load_index_packs_empty_zip(self, mock_request: MagicMock) -> None:
        """
        Given:
            - An index.zip with no pack folders.
        When:
            - Calling load_index_packs.
        Then:
            - Returns an empty dict.
        """
        buf = io.BytesIO()
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            z.writestr("index/README.md", "empty")
        mock_response = MagicMock()
        mock_response.content = buf.getvalue()
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        result = load_index_packs(verify_ssl=True)
        assert result == {}

    @patch("download_packs_and_docker_images.requests.request")
    def test_load_index_packs_skips_invalid_json(self, mock_request: MagicMock) -> None:
        """
        Given:
            - An index.zip where one metadata.json contains invalid JSON.
        When:
            - Calling load_index_packs.
        Then:
            - Skips the invalid entry and returns the valid ones.
        """
        buf = io.BytesIO()
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            z.writestr("index/good_pack/metadata.json", json.dumps({"id": "good_pack", "name": "Good"}))
            z.writestr("index/bad_pack/metadata.json", "NOT VALID JSON{{{")
        mock_response = MagicMock()
        mock_response.content = buf.getvalue()
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        result = load_index_packs(verify_ssl=True)
        assert len(result) == 1
        assert "Good" in result
        assert result["Good"]["id"] == "good_pack"


# ---------------------------------------------------------------------------
# Tests: zip_folder
# ---------------------------------------------------------------------------


class TestZipFolder:
    """Tests for the zip_folder function."""

    def test_zip_folder_creates_zip(self, tmp_path: Path) -> None:
        """
        Given:
            - A directory with two files.
        When:
            - Calling zip_folder.
        Then:
            - Creates a .zip file at output_path containing both files.
        """
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "file1.txt").write_text("hello")
        (source_dir / "file2.txt").write_text("world")

        output_base = str(tmp_path / "output")
        zip_folder(str(source_dir), output_base)

        zip_path = Path(output_base + ".zip")
        assert zip_path.is_file()

        with ZipFile(zip_path, "r") as z:
            names = z.namelist()
            assert "file1.txt" in names
            assert "file2.txt" in names

    def test_zip_folder_includes_nested_files(self, tmp_path: Path) -> None:
        """
        Given:
            - A directory with nested subdirectories containing files.
        When:
            - Calling zip_folder.
        Then:
            - All files (including nested) are included in the zip.
        """
        source_dir = tmp_path / "source"
        sub_dir = source_dir / "subdir"
        sub_dir.mkdir(parents=True)
        (source_dir / "root.txt").write_text("root")
        (sub_dir / "nested.txt").write_text("nested")

        output_base = str(tmp_path / "output")
        zip_folder(str(source_dir), output_base)

        zip_path = Path(output_base + ".zip")
        with ZipFile(zip_path, "r") as z:
            names = z.namelist()
            assert "root.txt" in names
            assert "subdir/nested.txt" in names

    def test_zip_folder_empty_directory(self, tmp_path: Path) -> None:
        """
        Given:
            - An empty directory.
        When:
            - Calling zip_folder.
        Then:
            - Creates a zip file with no entries.
        """
        source_dir = tmp_path / "empty"
        source_dir.mkdir()

        output_base = str(tmp_path / "output")
        zip_folder(str(source_dir), output_base)

        zip_path = Path(output_base + ".zip")
        assert zip_path.is_file()
        with ZipFile(zip_path, "r") as z:
            assert z.namelist() == []


# ---------------------------------------------------------------------------
# Tests: extract_docker_images_from_pack_zips
# ---------------------------------------------------------------------------


class TestExtractDockerImagesFromPackZips:
    """Tests for the extract_docker_images_from_pack_zips function."""

    def test_extracts_docker_images(self, tmp_path: Path) -> None:
        """
        Given:
            - A directory with a pack zip containing a YAML file with dockerimage fields.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns the set of docker images found.
        """
        yaml_content = "name: MyIntegration\n" "dockerimage: demisto/python3:3.10.13.12345\n"
        pack_zip_bytes = _build_pack_zip_with_yaml(yaml_content)
        (tmp_path / "TestPack.zip").write_bytes(pack_zip_bytes)

        result = extract_docker_images_from_pack_zips(str(tmp_path))

        assert "demisto/python3:3.10.13.12345" in result

    def test_extracts_from_scripts(self, tmp_path: Path) -> None:
        """
        Given:
            - A pack zip with a YAML file under Scripts/.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns the docker image from the script.
        """
        buf = io.BytesIO()
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            z.writestr(
                "Scripts/MyScript/MyScript.yml",
                "dockerimage: demisto/python:2.7.18.20958\n",
            )
        (tmp_path / "TestPack.zip").write_bytes(buf.getvalue())

        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == {"demisto/python:2.7.18.20958"}

    def test_ignores_non_yaml_files(self, tmp_path: Path) -> None:
        """
        Given:
            - A pack zip containing only non-YAML files with dockerimage strings.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns an empty set.
        """
        buf = io.BytesIO()
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            z.writestr("Integrations/MyInt/README.md", "dockerimage: demisto/python3:3.10.13.12345")
        (tmp_path / "TestPack.zip").write_bytes(buf.getvalue())

        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == set()

    def test_ignores_yaml_outside_integrations_and_scripts(self, tmp_path: Path) -> None:
        """
        Given:
            - A pack zip with YAML files under Playbooks/ and at root level.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns an empty set (only Integrations/ and Scripts/ are scanned).
        """
        buf = io.BytesIO()
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            z.writestr("Playbooks/playbook.yml", "dockerimage: demisto/python3:3.10.13.12345\n")
            z.writestr("root.yml", "dockerimage: demisto/python3:3.10.13.12345\n")
        (tmp_path / "TestPack.zip").write_bytes(buf.getvalue())

        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == set()

    def test_empty_directory(self, tmp_path: Path) -> None:
        """
        Given:
            - An empty directory with no zip files.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns an empty set.
        """
        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == set()

    def test_skips_invalid_docker_image_format(self, tmp_path: Path) -> None:
        """
        Given:
            - A YAML file with dockerimage values that lack ':' or '/'.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Those values are not included in the result.
        """
        yaml_content = "dockerimage: justanimage\n" "dockerimage: demisto/python3:3.10.13.12345\n"
        pack_zip_bytes = _build_pack_zip_with_yaml(yaml_content)
        (tmp_path / "TestPack.zip").write_bytes(pack_zip_bytes)

        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == {"demisto/python3:3.10.13.12345"}

    def test_deduplicates_docker_images(self, tmp_path: Path) -> None:
        """
        Given:
            - Multiple pack zips referencing the same docker image.
        When:
            - Calling extract_docker_images_from_pack_zips.
        Then:
            - Returns a set with unique entries only.
        """
        yaml_content = "dockerimage: demisto/python3:3.10.13.12345\n"
        pack_zip_bytes = _build_pack_zip_with_yaml(yaml_content)
        (tmp_path / "Pack1.zip").write_bytes(pack_zip_bytes)
        (tmp_path / "Pack2.zip").write_bytes(pack_zip_bytes)

        result = extract_docker_images_from_pack_zips(str(tmp_path))
        assert result == {"demisto/python3:3.10.13.12345"}


# ---------------------------------------------------------------------------
# Tests: get_pack_names
# ---------------------------------------------------------------------------


class TestGetPackNames:
    """Tests for the get_pack_names function."""

    def test_resolves_display_names_to_ids(self) -> None:
        """
        Given:
            - A list of valid pack display names.
        When:
            - Calling get_pack_names with index metadata.
        Then:
            - Returns a mapping of display_name -> pack_id.
        """
        result = get_pack_names(["Mock Pack", "Mock Pack 2"], MOCK_INDEX_PACKS)
        assert "Mock Pack" in result
        assert "Mock Pack 2" in result
        assert result["Mock Pack"]["id"] == "mock_pack"
        assert result["Mock Pack 2"]["id"] == "mock_pack_2"

    def test_skips_unknown_packs(self) -> None:
        """
        Given:
            - A list containing an unknown pack display name.
        When:
            - Calling get_pack_names.
        Then:
            - Skips the unknown pack and returns only the valid ones.
        """
        result = get_pack_names(["Mock Pack", "NonExistent Pack"], MOCK_INDEX_PACKS)
        assert len(result) == 1
        assert result["Mock Pack"]["id"] == "mock_pack"

    def test_empty_input_returns_all(self) -> None:
        """
        Given:
            - An empty string split into [''] (no specific packs requested).
        When:
            - Calling get_pack_names.
        Then:
            - Returns all packs from the index.
        """
        result = get_pack_names([""], MOCK_INDEX_PACKS)
        assert len(result) == 3
        assert "Mock Pack" in result
        assert "Mock Pack 2" in result
        assert "Deprecated Pack" in result

    def test_all_unknown_packs(self) -> None:
        """
        Given:
            - A list where no pack display names match the index.
        When:
            - Calling get_pack_names.
        Then:
            - Returns an empty dict.
        """
        result = get_pack_names(["Fake1", "Fake2"], MOCK_INDEX_PACKS)
        assert result == {}


# ---------------------------------------------------------------------------
# Tests: should_filter_out_pack
# ---------------------------------------------------------------------------


class TestShouldFilterOutPack:
    """Tests for the should_filter_out_pack function."""

    @pytest.mark.parametrize(
        "pack_data, fields, deprecated, expected",
        [
            pytest.param(
                PACK1_DATA_MOCK,
                {"field": "value", "field2": "value2"},
                False,
                False,
                id="not_removing-deprecated_pack-matching_fields-without_deprecated_flag",
            ),
            pytest.param(
                PACK1_DATA_MOCK,
                {"field": "other value", "field2": "value"},
                False,
                True,
                id="removing-deprecated_pack-non_matching_fields-without_deprecated_flag",
            ),
            pytest.param(
                PACK1_DATA_MOCK,
                {"field": "value", "field2": "value2"},
                True,
                True,
                id="removing-deprecated_pack-matching_fields-with_deprecated_flag",
            ),
            pytest.param(
                PACK1_DATA_MOCK,
                {"field": "value", "field2": "value2"},
                True,
                True,
                id="removing-deprecated_pack-matching_fields-with_deprecated_flag_2",
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {"field": "value", "field2": "value2"},
                False,
                False,
                id="not_removing-normal_pack-matching_fields-without_deprecated_flag",
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {"field": "other value", "field2": "value"},
                False,
                True,
                id="removing-normal_pack-non_matching_fields-without_deprecated_flag",
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {"field": "value", "field2": "value2"},
                True,
                False,
                id="not_removing-normal_pack-matching_fields-with_deprecated_flag",
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {"field": "other value", "field2": "value2"},
                True,
                True,
                id="removing-normal_pack-non_matching_fields-with_deprecated_flag",
            ),
        ],
    )
    def test_should_filter_out_pack(
        self,
        pack_data: dict,
        fields: dict,
        deprecated: bool,
        expected: bool,
    ) -> None:
        assert should_filter_out_pack(pack_data, fields, deprecated) == expected

    def test_empty_fields_never_filters(self) -> None:
        """
        Given:
            - Empty fields dict and remove_deprecated=False.
        When:
            - Calling should_filter_out_pack.
        Then:
            - Returns False (pack is not filtered out).
        """
        assert should_filter_out_pack(PACK2_DATA_MOCK, {}, False) is False

    def test_deprecated_flag_on_non_deprecated_pack(self) -> None:
        """
        Given:
            - A non-deprecated pack with remove_deprecated=True.
        When:
            - Calling should_filter_out_pack with matching fields.
        Then:
            - Returns False (pack is not deprecated, fields match).
        """
        assert should_filter_out_pack(PACK2_DATA_MOCK, {"field": "value"}, True) is False
