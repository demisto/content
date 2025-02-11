import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dill
from PIL import Image
import io
import traceback
from typing import Literal
from collections.abc import Iterable
import numpy as np
import cv2 as cv


URL_PHISHING_MODEL_NAME = "url_phishing_model"
MSG_EMPTY_NAME_OR_URL = "Empty logo name or/and logo image ID"
MSG_EMPTY_LOGO_NAME = "Empty logo name argument"
OOB_VERSION_INFO_KEY = 'oob_version'
OUT_OF_THE_BOX_MODEL_PATH = '/model/model_docker.pkl'
MALICIOUS_VERDICT = "malicious"
BENIGN_VERDICT = "benign"
SUSPICIOUS_VERDICT = "suspicious"

MSG_WRONG_CONFIGURATION = "Wrong configuration of the model"
MSG_TRANSFER_LOGO = "Transfer logo from demisto model into new docker model"
MSG_ERROR_READING_MODEL = "Error reading model %s from Demisto"
MSG_NEED_TO_KNOW_WHICH_ACTION = "Need to choose one of the action: Add logo/ Remove logo/ Modify logo/ Display logos"

KEY_ADD_LOGO = 'AddLogo'
KEY_REMOVE_LOGO = 'RemoveLogo'
KEY_DISPLAY_LOGOS = 'DisplayAllLogos'
KEY_MODIFY_LOGO = 'ModifiedDomainForLogo'


class Model:
    '''Abstract class that represents the class of the built-in phishing model.'''

    clf: Any  # sklearn.pipeline.Pipeline
    df_voc: dict
    top_domains: dict
    logos_dict: dict
    custom_logo_associated_domain: dict


class ModelData(dict[Literal['top_domains', 'logos_dict', 'custom_logo_associated_domain'], dict]):
    '''Abstract class that represents the format of the data stored in the server.'''


def b64encode_string(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def b64decode_string(string: str) -> str:
    return base64.b64decode(string.encode()).decode()


def load_old_model_data(encoded_model: str) -> ModelData:
    '''Update the model to the new version'''
    import warnings
    warnings.filterwarnings("ignore", module='sklearn')

    old_import = dill._dill._import_module
    dill._dill._import_module = lambda x, safe=False: old_import(x, safe=True)
    model = cast(Model, dill.loads(base64.b64decode(encoded_model.encode())))
    dill._dill._import_module = old_import

    return model_to_data(model)


def save_model_data(model_data: ModelData):
    """
    Encode base 64 the model and call load_oob_model_from_model64
    :param model: URL Phishing model
    :return: msg
    """
    res = demisto.executeCommand(
        'createMLModel',
        {
            'modelData': b64_encode(json.dumps(model_data)),
            'modelName': URL_PHISHING_MODEL_NAME,
            'modelLabels': [MALICIOUS_VERDICT, BENIGN_VERDICT],
            'modelOverride': 'true',
            'modelHidden': True,
            'modelType': 'url_phishing'
        }
    )
    if is_error(res):
        raise DemistoException(get_error(res))
    demisto.debug(f'Saved data: {res}')


def model_to_data(model: Model) -> ModelData:
    return cast(ModelData, {
        'top_domains': model.top_domains,
        'logos_dict': model.logos_dict,
        'custom_logo_associated_domain': model.custom_logo_associated_domain
    })


def load_data_from_docker(path=OUT_OF_THE_BOX_MODEL_PATH) -> ModelData:
    """
    Load model from docker
    :param path: path of the model in the docker
    :return: URL Phishing model
    """
    with open(path, 'rb') as f:
        return model_to_data(cast(Model, dill.load(f)))  # guardrails-disable-line


def load_data_from_xsoar() -> Optional[ModelData]:
    res = demisto.executeCommand("getMLModel", {"modelName": URL_PHISHING_MODEL_NAME})[0]
    if is_error(res):
        demisto.debug(f'Model not found: {get_error(res)}')
        return None
    extra_data = dict_safe_get(res, ('Contents', 'model', 'extra'))
    model_data = dict_safe_get(res, ('Contents', 'modelData'))

    if isinstance(extra_data, dict) and 'minor' in extra_data:  # this means the old model exists as a pickled object
        demisto.debug(f'Old model found. {extra_data=}')
        return load_old_model_data(model_data)
    return cast(ModelData, json.loads(b64_decode(model_data)))


def image_from_base64_to_bytes(base64_message: str):
    """
    Transform image from base64 string into bytes
    :param base64_message:
    :return:
    """
    return base64.b64decode(base64_message.encode())


def get_concat_logo_single_image(logo_list: Iterable[str]):
    byte_images = map(image_from_base64_to_bytes, logo_list)
    number_of_image_per_row = 5
    width_new, height_new = 300, 300
    images = [Image.open(io.BytesIO(image_bytes)) for image_bytes in byte_images]
    total_number_of_images = len(images)
    total_width = number_of_image_per_row * width_new
    max_height = (total_number_of_images // number_of_image_per_row + 1) * height_new
    new_im = Image.new('RGB', (total_width, max_height))
    number_image_x = 0
    x_offset = 0
    y_offset = 0
    new_size = (width_new, height_new)
    for im in images:
        im = im.resize(new_size)  # type:ignore[assignment]
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


def decode_image(base64_message: str) -> np.ndarray:
    """
    Decode image from base64 to numpy array of pixels
    :param base64_message: str representing the encoded image
    :return: numpy.narray representing the image
    """
    base64_message = base64.decodebytes(base64_message.encode())
    nparr = np.frombuffer(base64_message, np.uint8)
    return cv.imdecode(nparr, cv.IMREAD_GRAYSCALE)  # pylint: disable=E1101


def update_top_domain(top_domains: dict, remove_list, add_list):
    for item_to_remove in remove_list:
        if top_domains.get(item_to_remove, -1) == 0:
            top_domains.pop(item_to_remove, None)
    for item_to_add in add_list:
        top_domains.setdefault(item_to_add, 0)


def add_new_logo(model_data: ModelData, logo_name, logo_image_id, associated_domains):
    try:
        res = demisto.getFilePath(logo_image_id)
        with open(res['path'], 'rb') as file:
            logo_content = file.read()
        if logo_name in model_data['logos_dict']:
            return_error(f"The logo name {logo_name!r} is already in use. Please use another logo name.")
        encoded_image = base64.b64encode(logo_content).decode()
        imm_arr = decode_image(encoded_image)
        if imm_arr is None:
            raise DemistoException("The file is not a valid image.")
        model_data['logos_dict'][logo_name] = encoded_image
        model_data['custom_logo_associated_domain'][logo_name] = associated_domains
        update_top_domain(model_data['top_domains'], [], associated_domains)
        return f"Logo {logo_name!r} successfully added."
    except (ValueError, KeyError):
        return_error(f"File not found: {logo_image_id}")
    except Exception as e:
        return_error(f'Unable to use image. Error: {e}')


def remove_logo(model_data: ModelData, logo_name):
    if logo_name not in model_data['logos_dict'] or logo_name not in model_data['custom_logo_associated_domain']:
        return_error(f"Logo name {logo_name!r} not found.")
    update_top_domain(model_data['top_domains'], model_data['custom_logo_associated_domain'][logo_name], [])
    model_data['logos_dict'].pop(logo_name)
    model_data['custom_logo_associated_domain'].pop(logo_name)
    return f"Logo {logo_name!r} successfully removed."


def update_domain_for_custom_logo(model_data: ModelData, logo_name, associated_domains):
    if logo_name not in model_data['logos_dict'] or logo_name not in model_data['custom_logo_associated_domain']:
        return_error(f"Logo name {logo_name!r} not found.")
    update_top_domain(model_data['top_domains'], model_data['custom_logo_associated_domain'][logo_name], associated_domains)
    model_data['custom_logo_associated_domain'][logo_name] = associated_domains
    return f"Logo {logo_name!r} successfully modified."


def display_all_logos(model_data: ModelData):
    description = []
    for name in model_data['logos_dict']:
        custom_associated_logo = model_data['custom_logo_associated_domain'].get(name, '')
        description.append(
            "{} ({}, {})".format(name, 'Custom Logo', ','.join(custom_associated_logo))
            if name in model_data['custom_logo_associated_domain']
            else "{} ({})".format(name, 'Default Logo')
        )
    merged_logos = get_concat_logo_single_image(model_data['logos_dict'].values())
    return fileResult(filename=', '.join(description), data=merged_logos, file_type=entryTypes['image'])


def execute_action(model_data: ModelData, action, logo_name, logo_image_id, associated_domains):
    if action == KEY_ADD_LOGO:
        return add_new_logo(model_data, logo_name, logo_image_id, associated_domains)
    elif action == KEY_REMOVE_LOGO:
        return remove_logo(model_data, logo_name)
    elif action == KEY_MODIFY_LOGO:
        return update_domain_for_custom_logo(model_data, logo_name, associated_domains)
    return display_all_logos(model_data)


def verify_args(action, logo_image_id, logo_name):
    if (action == KEY_ADD_LOGO) and not (logo_image_id or logo_name):
        return_error(MSG_EMPTY_NAME_OR_URL)
    elif (action == KEY_REMOVE_LOGO) and (not logo_name):
        return_error(MSG_EMPTY_LOGO_NAME)
    elif (action == KEY_MODIFY_LOGO) and (not logo_name):
        return_error(MSG_EMPTY_LOGO_NAME)


def main():
    try:
        args = demisto.args()
        logo_image_id = args.get('logoImageId', '')
        logo_name = args.get('logoName', '')
        associated_domains = argToList(args.get('associatedDomains', ''))
        action = args.get('action')

        verify_args(action, logo_image_id, logo_name)

        model_data = load_data_from_xsoar() or load_data_from_docker()

        res = execute_action(model_data, action, logo_name, logo_image_id, associated_domains)

        if action != KEY_DISPLAY_LOGOS:
            save_model_data(model_data)

        return_results(res)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute URL Phishing script. Error: {str(ex)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
