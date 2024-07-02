import pytest
import builtins

from Utils.download_packs_and_docker_images import (
    create_content_item_id_set,
    get_docker_images_with_tag,
    get_pack_names,
    should_filter_out_pack
)

MOCK_ID_SET = {
    "integrations": [
        {
            "mock_integration": {
                "name": "mock_integration",
                "file_path": "Packs/mock_pack",
                "source": ["code.pan.run", "xsoar", "content"],
                "fromversion": "5.0.0",
                "pack": "mock_pack",
                "docker_image": "demisto/python3:3.9.8.24399",
            }
        },
        {
            "mock_integration_2": {
                "name": "mock_integration_2",
                "file_path": "Packs/mock_pack_2/",
                "source": ["code.pan.run", "xsoar", "content"],
                "fromversion": "5.0.0",
                "pack": "mock_pack2",
                "tests": ["No tests"],
            }
        },
    ],
    "scripts": [
        {
            "mock_script": {
                "name": "mock_script",
                "file_path": "Packs/mock_pack",
                "source": ["code.pan.run", "xsoar", "content"],
                "fromversion": "5.0.0",
                "pack": "mock_pack",
                "docker_image": "demisto/python:2.7.18.20958",
            }
        },
        {
            "mock_script_2": {
                "name": "mock_script_2",
                "file_path": "Packs/mock_script_2",
                "source": ["code.pan.run", "xsoar", "content"],
                "fromversion": "5.0.0",
                "pack": "mock_pack_2",
                "docker_image": "demisto/python:2.7.18.20958",
            }
        },
    ],
    "Packs": {
        "mock_pack": {
            "name": "mock pack",
            "current_version": "1.0.3",
            "source": ["code.pan.run", "xsoar", "content"],
            "ContentItems": {
                "integrations": ["mock_integration"],
                "scripts": ["mock_script"],
            },
        },
        "mock_pack_2": {
            "name": "mock pack 2",
            "current_version": "1.0.3",
            "source": ["code.pan.run", "xsoar", "content"],
            "ContentItems": {
                "integrations": ["mock_integration_2"],
                "scripts": ["mock_script_2"],
            },
        },
    },
}

PACK1_DATA_MOCK = {
    'name': 'Pack1 (Deprecated)',
    'field': 'value',
    'field2': 'value2',
}

PACK2_DATA_MOCK = {
    'name': 'Pack2',
    'field': 'value',
    'field2': 'value2',
}


@pytest.mark.usefixtures("mock_print_patch")
class TestDownloadPacksAndDockerImages:

    @pytest.fixture(autouse=True)
    def mock_print_setup(self, mocker):
        # Mocking the print function
        self.mock_print = mocker.patch.object(builtins, 'print')

    @pytest.mark.parametrize(
        "id_set, expected_output",
        [
            pytest.param(
                MOCK_ID_SET["integrations"],
                {
                    "mock_integration": {
                        "name": "mock_integration",
                        "file_path": "Packs/mock_pack",
                        "source": ["code.pan.run", "xsoar", "content"],
                        "fromversion": "5.0.0",
                        "pack": "mock_pack",
                        "docker_image": "demisto/python3:3.9.8.24399",
                    },
                    "mock_integration_2": {
                        "name": "mock_integration_2",
                        "file_path": "Packs/mock_pack_2/",
                        "source": ["code.pan.run", "xsoar", "content"],
                        "fromversion": "5.0.0",
                        "pack": "mock_pack2",
                        "tests": ["No tests"],
                    },
                },
                id="valid items"
            ),
            pytest.param(
                [],
                {},
                id="Empty item list"
            ),
        ]
    )
    def test_create_content_item_id_set(self, id_set, expected_output):
        """
        Test create_content_item_id_set function
        Given:
            - mock id_set with list of integrations
        When:
            - Building the id_set with the given integration
        Then:
            - Returns the item list as a dict
        """

        assert create_content_item_id_set(id_set) == expected_output

    @pytest.mark.parametrize(
        "packs, print_res, expected_res",
        [
            pytest.param(
                {"d_mock": "mock_pack", "d_mock_2": "mock_pack_2"},
                "\t\tdemisto/python:2.7.18.20958 - used by mock_script_2",
                {
                    "demisto/python3:3.9.8.24399",
                    "demisto/python:2.7.18.20958",
                },
                id="duplicate valid items"
            ),
            pytest.param(
                set(),
                "\tPack d_no_pack was not found in id_set.json.",
                {"d_no_pack": "no_pack"},
                id="Empty item list"
            ),
        ]
    )
    def test_get_docker_images_with_tag(self, packs, print_res, expected_res):
        """
        Test get_docker_images_with_tag function
        Given:
            - list of packs
        When:
            - Getting docker images
        Then:
            - Returns the expected set of dockers with matching printing message.
        """

        actual_docker_images = get_docker_images_with_tag(packs, MOCK_ID_SET)
        self.mock_print.assert_called_with(print_res)

        assert actual_docker_images == expected_res

    def test_get_pack_names(self):
        """Test get_pack_names function"""
        pack_display_name, pack_display_name_2, invalid_pack = (
            "mock pack",
            "mock pack 2",
            "invalid_pack",
        )
        pack_name, pack_name_2 = "mock_pack", "mock_pack_2"
        expected = {pack_display_name: pack_name, pack_display_name_2: pack_name_2}
        res = get_pack_names(
            [pack_display_name, pack_display_name_2, invalid_pack], MOCK_ID_SET
        )
        assert res == expected
        self.mock_print.assert_called_with("Couldn't find pack invalid pack. Skipping pack.")

    @pytest.mark.parametrize(
        "pack_data, fields, deprecated, expected",
        [
            pytest.param(
                PACK1_DATA_MOCK,
                {'field': 'value', 'field2': 'value2'},
                False,
                False,
                id="not removing - Deprecated pack, multiple fields, without deprecated"
            ),
            pytest.param(
                PACK1_DATA_MOCK,
                {'field': 'other value', 'field2': 'value'},
                False,
                True,
                id="removing - Deprecated pack, multiple fields, not matching, without deprecated"
            ),
            pytest.param(
                PACK1_DATA_MOCK,
                {'field': 'value', 'field2': 'value2'},
                True,
                True,
                id="removing - Deprecated pack, multiple fields with deprecated"
            ),

            pytest.param(
                PACK1_DATA_MOCK,
                {'field': 'value', 'field2': 'value2'},
                True,
                True,
                id="removing - Deprecated pack, multiple fields, not matching, with deprecated"
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {'field': 'value', 'field2': 'value2'},
                False,
                False,
                id="not removing - multiple fields, without deprecated"
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {'field': 'other value', 'field2': 'value'},
                False,
                True,
                id="removing - multiple fields, not matching, without deprecated"
            ),
            pytest.param(
                PACK2_DATA_MOCK,
                {'field': 'value', 'field2': 'value2'},
                True,
                False,
                id="not removing - multiple fields with deprecated"
            ),

            pytest.param(
                PACK2_DATA_MOCK,
                {'field': 'other value', 'field2': 'value2'},
                True,
                True,
                id="removing - multiple fields, not matching, with deprecated"
            ),
        ]
    )
    def test_should_filter_out_pack(self, pack_data, fields, deprecated, expected):
        assert should_filter_out_pack(pack_data, fields, deprecated) == expected
