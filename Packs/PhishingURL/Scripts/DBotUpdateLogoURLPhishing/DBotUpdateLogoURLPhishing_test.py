from pytest_mock import MockerFixture
import base64

MODEL_DATA = {"top_domains": {}, "logos_dict": {}, "custom_logo_associated_domain": {}}


def load_image(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def test_add_new_logo(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import add_new_logo

    mocker.patch("demisto.getFilePath", return_value={"path": "test_data/logo.png"})
    model_data = MODEL_DATA.copy()
    logo_name = "PANW"
    logo_image_id = "<file_id>"
    associated_domains = ["domain1.com", "domain2.com"]

    res = add_new_logo(model_data, logo_name, logo_image_id, associated_domains)

    assert res == "Logo 'PANW' successfully added."
    assert model_data["top_domains"] == dict.fromkeys(associated_domains, 0)
    assert model_data["logos_dict"]["PANW"] == load_image("test_data/logo.png")
    assert model_data["custom_logo_associated_domain"]["PANW"] == associated_domains


def test_remove_logo(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import add_new_logo, remove_logo

    mocker.patch("demisto.getFilePath", return_value={"path": "test_data/logo.png"})
    model_data = MODEL_DATA.copy()
    logo_name = "PANW"
    add_new_logo(model_data, logo_name, "<file_id>", ["domain1.com", "domain2.com"])

    res = remove_logo(model_data, logo_name)

    assert res == "Logo 'PANW' successfully removed."
    assert model_data == MODEL_DATA


def test_update_domain_for_custom_logo():
    from DBotUpdateLogoURLPhishing import update_domain_for_custom_logo

    logo_name = "PANW"
    old_associated_domains = ["domain1.com"]
    new_associated_domains = ["domain2.com"]
    model_data = MODEL_DATA.copy()
    model_data["top_domains"] = dict.fromkeys(old_associated_domains, 0)
    model_data["custom_logo_associated_domain"][logo_name] = old_associated_domains

    res = update_domain_for_custom_logo(model_data, logo_name, new_associated_domains)

    assert res == "Logo 'PANW' successfully modified."
    assert model_data["top_domains"] == dict.fromkeys(new_associated_domains, 0)
    assert (
        model_data["custom_logo_associated_domain"][logo_name] == new_associated_domains
    )


def test_display_all_logos(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import display_all_logos

    mocked_file_result = mocker.patch("DBotUpdateLogoURLPhishing.fileResult")
    model_data = MODEL_DATA.copy()
    model_data["custom_logo_associated_domain"] = {1: "domain1.com"}
    model_data["logos_dict"] = dict.fromkeys(range(3), load_image("test_data/logo.png"))

    display_all_logos(model_data)

    mocked_file_result.assert_awaited_once_with(
        filename=", ".join(description),  # TODO
        data=load_image("test_data/image.png"),
        file_type=7,
    )


def test_load_data_from_xsoar(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import load_data_from_xsoar

    mocker.patch(
        "demisto.executeCommand",
        return_value=[{"Contents": {"ModelData": '["model_data"]'}}],
    )
    
    res = load_data_from_xsoar()
    
    assert res == ["model_data"]


def test_load_data_from_xsoar_no_data(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import load_data_from_xsoar

    mocker.patch("demisto.executeCommand", return_value=[{"Type": 4}])
    
    res = load_data_from_xsoar()
    
    assert res is None


def test_load_data_from_xsoar_old_data(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import load_data_from_xsoar

    mocker.patch("demisto.executeCommand", return_value=[{"Type": 4}])
    mock_loader = mocker.patch(
        "DBotUpdateLogoURLPhishing.load_old_model_data",
        return_value=[{"Contents": {"ModelData": "model_data"}}],
    )

    load_data_from_xsoar()

    mock_loader.assert_called_once_with("model_data")
