import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dill
from PIL import Image
import io
import traceback

MAJOR_VERSION = 1
MINOR_DEFAULT_VERSION = 0

URL_PHISHING_MODEL_NAME = "url_phishing_model"
MSG_EMPTY_NAME_OR_URL = "Empty logo name or/and logo image ID"
MSG_EMPTY_LOGO_NAME = "Empty logo name argument"
OOB_VERSION_INFO_KEY = 'oob_version'
OOB_MAJOR_VERSION_INFO_KEY = 'major'
OOB_MINOR_VERSION_INFO_KEY = 'minor'
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
MALICIOUS_VERDICT = "malicious"
BENIGN_VERDICT = "benign"
SUSPICIOUS_VERDICT = "suspicious"

MSG_ID_NOT_EXIST = "File ID does not seems to exist"
MSG_WRONG_CONFIGURATION = "Wrong configuration of the model"
MSG_SAVE_MODEL_IN_DEMISTO = "Saved model version %s.%s"
MSG_TRANSFER_LOGO = "Transfer logo from demisto model into new docker model"
MSG_ERROR_READING_MODEL = "Error reading model %s from Demisto"
MSG_NEED_TO_KNOW_WHICH_ACTION = "Need to choose one of the action: Add logo/ Remove logo/ Modify logo/ Display logos"
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'

KEY_ADD_LOGO = 'AddLogo'
KEY_REMOVE_LOGO = 'RemoveLogo'
KEY_DISPLAY_LOGOS = 'DisplayAllLogos'
KEY_MODIFY_LOGO = 'ModifiedDomainForLogo'


def get_minor_version_upgrade(model):
    model.minor = model.minor + 1
    return model.minor, model


def load_oob_model_from_model64(encoded_model, major, minor):
    """
    Save model in demisto
    :param encoded_model: model base64
    :param major:  major version
    :param minor: minor version
    :return: msg
    """
    res = demisto.executeCommand('createMLModel', {
        'modelData': encoded_model.decode('utf-8'),
        'modelName': URL_PHISHING_MODEL_NAME,
        'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
        'modelOverride': 'true',
        'modelHidden': True,
        'modelType': 'url_phishing',
        'modelExtraInfo': {
            OOB_MAJOR_VERSION_INFO_KEY: major,
            OOB_MINOR_VERSION_INFO_KEY: minor
        }})
    if is_error(res):
        raise DemistoException(get_error(res))
    return MSG_SAVE_MODEL_IN_DEMISTO % (str(major), str(minor))


def save_upgraded_version_model(model):
    """
    Encode base 64 the model and call load_oob_model_from_model64
    :param model: URL Phishing model
    :return: msg
    """
    model_bytes = dill.dumps(model)  # guardrails-disable-line
    model_64 = base64.b64encode(model_bytes)
    msg = load_oob_model_from_model64(model_64, model.major, model.minor)
    return msg


def get_model_data(model_name: str):
    """
    Return model data saved in demisto (string of encoded base 64)
    :param model_name: name of the model to load from demisto
    :return: str, str
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if is_error(res_model):
        raise DemistoException(MSG_ERROR_READING_MODEL % model_name)
    else:
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE


def oob_model_exists_and_updated():
    """
    Check is the model exist and is updated in demisto
    :return: bool, int, int
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res_model):
        return False, -1, -1
    existing_model_version_major = res_model['Contents']['model']['extra'].get(OOB_MAJOR_VERSION_INFO_KEY, -1)
    existing_model_version_minor = res_model['Contents']['model']['extra'].get(OOB_MINOR_VERSION_INFO_KEY, -1)
    return True, existing_model_version_major, existing_model_version_minor


def load_demisto_model():
    """
    Load base64 demisto model and decode it
    :return: URL Phishing model
    """
    model_64_str = get_model_data(URL_PHISHING_MODEL_NAME)[0]
    model = decode_model_data(model_64_str)
    return model


def decode_model_data(model_data: str):
    """
    Decode the base 64 version of the model
    :param model_data: string of the encoded based 64 model
    :return: URL Phishing model
    """
    return dill.loads(base64.b64decode(model_data.encode('utf-8')))  # guardrails-disable-line


def load_model_from_docker(path=OUT_OF_THE_BOX_MODEL_PATH):
    """
    Load model from docker
    :param path: path of the model in the docker
    :return: URL Phishing model
    """
    model = dill.load(open(path, 'rb'))  # guardrails-disable-line
    return model


def image_from_base64_to_bytes(base64_message: str):
    """
    Transform image from base64 string into bytes
    :param base64_message:
    :return:
    """
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes


def get_concat_logo_single_image(logo_list):
    number_of_image_per_row = 5
    width_new, height_new = 300, 300
    images = [Image.open(io.BytesIO(image_bytes)) for image_bytes in logo_list]
    total_number_of_images = len(images)
    total_width = number_of_image_per_row * width_new
    max_height = (total_number_of_images // number_of_image_per_row + 1) * height_new
    new_im = Image.new('RGB', (total_width, max_height))
    number_image_x = 0
    x_offset = 0
    y_offset = 0
    new_size = (width_new, height_new)
    for im in images:
        im = im.resize(new_size)
        if number_image_x >= number_of_image_per_row:
            x_offset = 0
            y_offset += height_new
            number_image_x = 0
        new_im.paste(im, (x_offset, y_offset))
        x_offset += width_new
        number_image_x += 1
    buf = io.BytesIO()
    new_im.save(buf, format='JPEG')
    return buf.getvalue()


def display_all_logos(model):
    description = ""
    logo_list = []
    for name, logo in model.logos_dict.items():
        custom_associated_logo = model.custom_logo_associated_domain.get(name, '')
        if name in model.custom_logo_associated_domain.keys():
            description = description + ", %s (%s, %s)" % (name, 'Custom Logo', ','.join(custom_associated_logo))
        else:
            description = description + ", %s (%s)" % (name, 'Default Logo')
        logo_list.append(logo)
    description = description[1:]
    merged_logos = get_concat_logo_single_image([image_from_base64_to_bytes(logo) for logo in logo_list])
    res = fileResult(filename=description, data=merged_logos)
    res['Type'] = entryTypes['image']
    return_results(res)


def execute_action(action, logo_name, logo_content, associated_domains, model):
    if action == KEY_ADD_LOGO:
        success, msg = model.add_new_logo(logo_name, logo_content, associated_domains)
    elif action == KEY_REMOVE_LOGO:
        success, msg = model.remove_logo(logo_name)
    else:
        success, msg = model.update_domain_for_custom_logo(logo_name, associated_domains)
    return success, msg


def main():
    try:
        msg_list = []
        logo_image_id = demisto.args().get('logoImageId', '')
        logo_name = demisto.args().get('logoName', '')
        associated_domains = demisto.args().get('associatedDomains', '').split(',')
        action = demisto.args().get('action', None)

        if action == KEY_DISPLAY_LOGOS:
            exist, _, _ = oob_model_exists_and_updated()
            if exist:
                model = load_demisto_model()
            else:
                model = load_model_from_docker()
            display_all_logos(model)
            return

        if (action == KEY_ADD_LOGO) and (not logo_image_id or not logo_name):
            return_error(MSG_EMPTY_NAME_OR_URL)
        if (action == KEY_REMOVE_LOGO) and (not logo_name):
            return_error(MSG_EMPTY_LOGO_NAME)
        if (action == KEY_MODIFY_LOGO) and (not logo_name):
            return_error(MSG_EMPTY_LOGO_NAME)

        if action == KEY_ADD_LOGO:
            try:
                res = demisto.getFilePath(logo_image_id)
                path = res['path']
                with open(path, 'rb') as file:
                    logo_content = file.read()
            except ValueError:
                return_error(MSG_ID_NOT_EXIST)
        else:
            logo_content = bytearray()

        exist, demisto_major_version, demisto_minor_version = oob_model_exists_and_updated()

        # Case 1: model in demisto does not exist OR new major released but no logo were added -> load from docker
        if not exist or (demisto_major_version < MAJOR_VERSION and demisto_minor_version == MINOR_DEFAULT_VERSION):
            model = load_model_from_docker()
            success, msg = execute_action(action, logo_name, logo_content, associated_domains, model)
            msg_list.append(msg)
            if success:
                minor, model = get_minor_version_upgrade(model)
                msg = save_upgraded_version_model(model)
                msg_list.append(msg)
            else:
                return_error(msg)

        # Case where there were new new model release -> load model from demisto
        elif (demisto_major_version == MAJOR_VERSION):
            model = load_demisto_model()
            success, msg = execute_action(action, logo_name, logo_content, associated_domains, model)
            msg_list.append(msg)
            if success:
                minor, model = get_minor_version_upgrade(model)
                msg = save_upgraded_version_model(model)
                msg_list.append(msg)
            else:
                return_error(msg)

        # Case where new model release and logo were added -> transfer logo from model in demisto to new model in docker
        elif (demisto_major_version < MAJOR_VERSION) and (demisto_minor_version > MINOR_DEFAULT_VERSION):
            model_docker = load_model_from_docker()
            model_demisto = load_demisto_model()
            model_docker.logos_dict = model_demisto.logos_dict
            model_docker.custom_logo_associated_domain = model_demisto.custom_logo_associated_domain
            model_docker.top_domains = model_demisto.top_domains
            msg_list.append(MSG_TRANSFER_LOGO)
            success, msg = execute_action(action, logo_name, logo_content, associated_domains, model_docker)
            msg_list.append(msg)
            if success:
                model_docker.minor = demisto_minor_version
                minor, model_docker = get_minor_version_upgrade(model_docker)
                msg = save_upgraded_version_model(model_docker)
                msg_list.append(msg)
            else:
                return_error(msg)
                msg_list.append(msg)

        else:
            msg_list.append(MSG_WRONG_CONFIGURATION)
            return_error(MSG_WRONG_CONFIGURATION)
        return_results(' , '.join(msg_list))
        return msg_list
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute URL Phishing script. Error: {str(ex)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
