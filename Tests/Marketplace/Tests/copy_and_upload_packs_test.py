import pytest


# disable-secrets-detection-start
class TestGetPackNames:
    @pytest.mark.parametrize("packs_names_input, expected_result", [
        ("pack1,pack2,pack1", {"pack1", "pack2"}),
        ("pack1, pack2,  pack3", {"pack1", "pack2", "pack3"})
    ])
    def test_get_packs_names_specific(self, packs_names_input, expected_result):
        from Tests.Marketplace.copy_and_upload_packs import get_pack_names
        modified_packs = get_pack_names(packs_names_input)

        assert modified_packs == expected_result
# disable-secrets-detection-end
