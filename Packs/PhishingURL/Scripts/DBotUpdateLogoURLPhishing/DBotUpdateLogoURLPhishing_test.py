from pytest_mock import MockerFixture
import demistomock as demisto
import base64

MODEL_DATA = {
    'top_domains': {},
    'logos_dict': {},
    'custom_logo_associated_domain': {}
}

# class PhishingURLModelMock:
#     def __init__(self, top_domains=None, logos_dict=None, minor=0, major=0, custom_logo_associated_domain={}):
#         self.top_domains = top_domains
#         self.logos_dict = logos_dict
#         self.major = major
#         self.minor = minor
#         self.custom_logo_associated_domain = custom_logo_associated_domain

#     def add_new_logo(self, logo_name, logo_url, associated_domain):
#         return True, MSG_LOGO_ADDED

#     def remove_logo(self, logo_name):
#         return True, MSG_LOGO_REMOVED

#     def update_domain_for_custom_logo(self, logo_name, associated_domains):
#         return True, MSG_LOGO_AMENDED


def test_new_logo_added(mocker: MockerFixture):
    from DBotUpdateLogoURLPhishing import add_new_logo
    # add_new_logo(model_data: ModelData, logo_name, logo_image_id, associated_domains):
    
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/logo.png"})
    
    model_data = MODEL_DATA.copy()
    logo_name = 'PANW'
    logo_image_id = '<file_id>'
    associated_domains = ['domain1.com', 'domain2.com']
    
    res = add_new_logo(model_data, logo_name, logo_image_id, associated_domains)
    
    assert res == "Logo 'PANW' successfully added."
    assert model_data['top_domains'] == None  # TODO
    assert model_data['logos_dict'] == None  # TODO
    assert model_data['custom_logo_associated_domain'] == None  # TODO


# def test_remove_logo():
#     from DBotUpdateLogoURLPhishing import add_new_logo, remove_logo
#     model_data = MODEL_DATA.copy()
#     logo_name = 'PANW'

#     remove_logo(model_data, logo_name)

# def test_update_domain_for_custom_logo(): ...
# def test_test_display_all_logos(): ...

# def test_new_major_no_added_logo(mocker):
#     current_major_version = 0
#     current_minor_version = 0
#     docker_version = 2
#     model_mock_docker = PhishingURLModelMock(major=2, minor=0)
#     model_mock_demisto = PhishingURLModelMock(major=0, minor=0)
#     mocker.patch.object(demisto, 'args', return_value={'logoName': 'url_name',
#                                                        'action': KEY_ADD_LOGO, 'logoImageId': 'logo_id'})
#     mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
#                  return_value=(True, current_major_version, current_minor_version), create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
#     mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/logo.png"})
#     msg_list = main()
#     assert MSG_LOGO_ADDED in msg_list
#     assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
#     assert MSG_TRANSFER_LOGO not in msg_list


# def test_same_major_added_logo(mocker):
#     current_major_version = 1
#     current_minor_version = 3
#     docker_version = 1
#     model_mock_docker = PhishingURLModelMock(major=1, minor=0)
#     model_mock_demisto = PhishingURLModelMock(major=1, minor=3)
#     mocker.patch.object(demisto, 'args', return_value={'logoName': 'url_name',
#                                                        'action': KEY_ADD_LOGO, 'logoImageId': 'logo_id'})
#     mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
#                  return_value=(True, current_major_version, current_minor_version), create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
#     mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/logo.png"})
#     msg_list = main()
#     assert MSG_LOGO_ADDED in msg_list
#     assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
#     assert MSG_TRANSFER_LOGO not in msg_list


# def test_add_logo_with_associated_domain(mocker):
#     current_major_version = 0
#     current_minor_version = 1
#     docker_version = 1
#     model_mock_docker = PhishingURLModelMock(major=1, minor=0)
#     model_mock_demisto = PhishingURLModelMock(major=0, minor=1)
#     mocker.patch.object(demisto, 'args', return_value={'logoName': 'url_name',
#                                                        'associatedDomains': 'custom_domain',
#                                                        'action': KEY_ADD_LOGO, 'logoImageId': 'logo_id'})
#     mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
#                  return_value=(True, current_major_version, current_minor_version), create=True)
#     mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
#     mocker.patch.object(demisto, 'getFilePath', return_value={"path": "test_data/logo.png"})
#     msg_list = main()
#     assert MSG_LOGO_ADDED in msg_list
#     assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
#     assert MSG_TRANSFER_LOGO in msg_list


def test_get_concat_logo_single_image(mocker):
    path = "test_data/logo.png"
    with open(path, 'rb') as file:
        logo_content = file.read()
    logo_list = [logo_content] * 3
    concat_image_found = get_concat_logo_single_image(logo_list)
    with open('test_data/image.png', 'rb') as f:
        image_concat_true = f.read()
    assert concat_image_found == image_concat_true


def test_display_all_logos(mocker):
    current_major_version = 0
    current_minor_version = 1
    path = "test_data/logo.png"
    with open(path, 'rb') as file:
        logo_content = base64.b64encode(file.read()).decode('utf-8')
    p_logos_dict = {'logo_1': logo_content, 'logo_2': logo_content, 'logo_3': logo_content}
    model_mock_docker = PhishingURLModelMock(major=0, minor=0)
    model_mock_demisto = PhishingURLModelMock(top_domains=None, logos_dict=p_logos_dict, minor=1, major=0,
                                              custom_logo_associated_domain={})
    mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
                 return_value=(True, current_major_version, current_minor_version), create=True)
    mocker.patch.object(demisto, 'args', return_value={'action': KEY_DISPLAY_LOGOS})
    main()
    

def test_load_data_from_xsoar(): ...
