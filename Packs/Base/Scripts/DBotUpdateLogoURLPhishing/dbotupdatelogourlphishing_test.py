from DBotUpdateLogoURLPhishing import *

MSG_LOGO_ADDED = "Logo was add successfully"


class PhishingURLModelMock:
    def __init__(self, top_domains=None, logos_dict=None, minor=0, major=0):
        self.top_domains = top_domains
        self.logos_dict = logos_dict
        self.major = major
        self.minor = minor

    def add_new_logo(self, logo_name, logo_url):
        return True, "Logo was add successfully"


def test_new_major_logo_added(mocker):
    current_major_version = 0
    current_minor_version = 1
    docker_version = 1
    model_mock_docker = PhishingURLModelMock(major=1, minor=0)
    model_mock_demisto = PhishingURLModelMock(major=0, minor=1)
    mocker.patch.object(demisto, 'args', return_value={'logoImageURL': 'url_image', 'logoName': 'url_name'})
    mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
                 return_value=(True, current_major_version, current_minor_version), create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
    msg_list = main()
    assert MSG_LOGO_ADDED in msg_list
    assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
    assert MSG_TRANSFER_LOGO in msg_list


def test_same_major_no_added_logo(mocker):
    current_major_version = 0
    current_minor_version = 0
    docker_version = 0
    model_mock_docker = PhishingURLModelMock(major=0, minor=0)
    model_mock_demisto = PhishingURLModelMock(major=0, minor=0)
    mocker.patch.object(demisto, 'args', return_value={'logoImageURL': 'url_image', 'logoName': 'url_name'})
    mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
                 return_value=(True, current_major_version, current_minor_version), create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
    msg_list = main()
    assert MSG_LOGO_ADDED in msg_list
    assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
    assert MSG_TRANSFER_LOGO not in msg_list


def test_new_major_no_added_logo(mocker):
    current_major_version = 0
    current_minor_version = 0
    docker_version = 2
    model_mock_docker = PhishingURLModelMock(major=2, minor=0)
    model_mock_demisto = PhishingURLModelMock(major=0, minor=0)
    mocker.patch.object(demisto, 'args', return_value={'logoImageURL': 'url_image', 'logoName': 'url_name'})
    mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
                 return_value=(True, current_major_version, current_minor_version), create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
    msg_list = main()
    assert MSG_LOGO_ADDED in msg_list
    assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
    assert MSG_TRANSFER_LOGO not in msg_list


def test_same_major_added_logo(mocker):
    current_major_version = 1
    current_minor_version = 3
    docker_version = 1
    model_mock_docker = PhishingURLModelMock(major=1, minor=0)
    model_mock_demisto = PhishingURLModelMock(major=1, minor=3)
    mocker.patch.object(demisto, 'args', return_value={'logoImageURL': 'url_image', 'logoName': 'url_name'})
    mocker.patch('DBotUpdateLogoURLPhishing.load_model_from_docker', return_value=model_mock_docker, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.load_demisto_model', return_value=model_mock_demisto, create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.oob_model_exists_and_updated',
                 return_value=(True, current_major_version, current_minor_version), create=True)
    mocker.patch('DBotUpdateLogoURLPhishing.MAJOR_VERSION', docker_version)
    msg_list = main()
    assert MSG_LOGO_ADDED in msg_list
    assert MSG_SAVE_MODEL_IN_DEMISTO % (str(docker_version), str(current_minor_version + 1))
    assert MSG_TRANSFER_LOGO not in msg_list
