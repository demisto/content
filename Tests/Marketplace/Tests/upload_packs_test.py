import pytest
from Tests.Marketplace.upload_packs import get_modified_packs


# disable-secrets-detection-start
class TestModifiedPacks:
    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_modified_packs_specific(self, packs_names_input, expected_result):
        modified_packs = get_modified_packs(packs_names_input)

        assert modified_packs == expected_result

    @pytest.mark.parametrize("packs_names_input", [None, ""])
    def test_get_modified_packs_empty(self, mocker, packs_names_input):
        modified_packs_return_value = ("Packs/Pack1/pack_metadata.json\n"
                                       "Packs/Pack1/Integrations/Integration1/CHANGELOG.md\n"
                                       "Packs/Pack2/pack_metadata.json\n")
        mocker.patch('Tests.Marketplace.upload_packs.run_command', return_value=modified_packs_return_value)
        modified_packs = get_modified_packs()

        assert modified_packs == {"Pack1", "Pack2"}
# disable-secrets-detection-end
