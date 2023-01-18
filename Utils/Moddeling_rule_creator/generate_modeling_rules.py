import pandas as pd
import json
import logging
from typing import List

logging.basicConfig(level=logging.INFO)

VENDOR = "microsoft"
PRODUCT = "defender_for_cloud"

base_path = '/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/'
outputfile_schema = base_path + f'{VENDOR}_{PRODUCT}_modeling_rules.json'
outputfile_xif = base_path + f'{VENDOR}_{PRODUCT}_modeling_rules.xif'
outputfile_yml = base_path + f'{VENDOR}_{PRODUCT}_modeling_rules.yml'

sdk_from_version = '6.10.0'
DATASET_NAME = f'{VENDOR.lower()}_{PRODUCT.lower()}_raw'


class MappingField():

    def __init__(self, xdm_rule, field_path_raw, xdm_field_type, xdm_class_type, is_array_raw, type_raw):
        self.xdm_rule = xdm_rule
        self.field_path_raw = field_path_raw
        self.xdm_field_type = xdm_field_type
        self.xdm_class_type = xdm_class_type
        self.is_array_raw = is_array_raw
        self.type_raw = type_raw

    def create_schema_types(self) -> dict:
        return {
            "type": self.type_raw,
            "is_array": self.is_array_raw
        }


def to_string(s: str) -> str:
    """
    Gets a xql and wraps it with a to_string function
    """
    return f'to_string({s})'


def to_number(s: str) -> str:
    """
    Gets a xql and wraps it with a to_number function """
    return f'to_number({s})'


def json_extract_array(prefix: str, suffix: str) -> str:
    return f'json_extract_array({prefix}, "$.{suffix}")'


def json_extract_scalar(prefix: str, suffix: str) -> str:
    return f'json_extract_scalar({prefix}, "$.{suffix}")'


def array_create(s: str) -> str:
    return f'arraycreate({s})'


def create_xif_header() -> str:
    """
    Creates the xif header 
    """
    xif_rule = ''
    xif_rule += f'[MODEL: dataset={DATASET_NAME}]\n'
    xif_rule += '| alter\n'
    return xif_rule


def convert_raw_type_to_xdm_type(schema_type: str) -> str:
    """
    returns the xdm type convention
    """
    converting_dict = {
        'string': 'String',
        'int': 'Number',
        'boolean': 'Boolean'
    }

    return converting_dict.get(schema_type, 'String')


def convert_to_xdm_type(name: str, xdm_type: str) -> str:
    if xdm_type == 'String':
        name = to_string(name)
    elif xdm_type == 'Number':
        name = to_number(name)

    return name


def create_xif_file(mapping_list: List[MappingField]) -> None:
    """
    Created the xif file for the modeling rules
    """
    logging.info('Generating xif file\n')
    xif_rule = create_xif_header()
    for mapping_rule in mapping_list:
        logging.info(f'xdm type: {mapping_rule.xdm_field_type} - raw type {mapping_rule.type_raw}')
        name = mapping_rule.field_path_raw

        if '.' in mapping_rule.field_path_raw:
            dict_keys = mapping_rule.field_path_raw.split('.')
            prefix = dict_keys[0]
            suffix = '.'.join(dict_keys[1:])
            if mapping_rule.xdm_class_type == 'Array':
                name = json_extract_array(prefix, suffix)
            else:
                name = json_extract_scalar(prefix, suffix)

        if mapping_rule.xdm_field_type != convert_raw_type_to_xdm_type(mapping_rule.type_raw):
            name = convert_to_xdm_type(name, mapping_rule.xdm_field_type)

        xif_rule += f'\t{mapping_rule.xdm_rule} = {name},\n'

    xif_rule = replace_last_char(xif_rule)

    with open(outputfile_xif, 'w') as f:
        f.write(xif_rule)


def replace_last_char(s: str) -> str:
    """
    Replaces the last char of the xif file to be ;
    """
    s = s[:-2]
    s += ';\n'
    return s


def create_scheme_file(mapping_list: List[MappingField]):
    """
    Creates the .json schema file
    """
    logging.info('creating modeling rules schema\n')
    name_type_dict = {}
    for mapping_rule in mapping_list:
        keys_list = mapping_rule.field_path_raw.split('.')
        name = keys_list[0]
        if name not in name_type_dict:
            name_type_dict[name] = mapping_rule.create_schema_types()
    modeling_rules_xif = {DATASET_NAME: name_type_dict}

    with open(outputfile_schema, 'w') as f:
        res = json.dumps(modeling_rules_xif, indent=4)
        f.write(res)


def process_yml_name():
    name = f"{PRODUCT} {VENDOR} Modeling Rule\n"
    name = name.replace('_', ' ')
    list_names = name.split()
    capitalized_name_list = []
    for name in list_names:
        capitalized_name_list.append(name.capitalize())
    return ' '.join(capitalized_name_list)


def get_types(d):
    types = {}
    for key, value in d.items():
        if isinstance(value, dict):
            types[key] = get_types(value)
        else:
            types[key] = type(value)
    return types


def create_yml_file():
    logging.info('creating modeing rules yml file\n')
    yml_file = (f"fromversion: {sdk_from_version}\n"
                f"id: {PRODUCT}_{VENDOR}_modeling_rule\n"
                f"name: {process_yml_name()}\n"
                "rules: ''\n"
                "schema: ''\n"
                f"tags: {PRODUCT}\n")

    with open(outputfile_yml, 'w') as f:
        f.write(yml_file)


def discoverType(value) -> str:
    if isinstance(value, list):
        return 'array'
    elif isinstance(value, bool):
        return 'bool'
    elif isinstance(value, int):
        return 'int'
    return 'string'


def extract_raw_type_data(event, keys_from_modeling: str):
    keys_split = keys_from_modeling.split('.')
    temp = event
    for key in keys_split:
        if isinstance(temp, dict):
            temp = temp.get(key)
        else:
            # for example when we have an array inside of a dict
            logging.info(f'{key=} is not of type dict')
            temp = None

    discovered = discoverType(temp)
    if discovered == 'array':
        if temp:
            inner_array_type = discoverType(temp[0])
            return inner_array_type, True
    return discovered, False


def extract_data_from_all_xdm_schema(path: str) -> tuple:
    schema_all_dict = pd.read_csv(path)

    columns_to_keep = ['name', 'datatype', 'dataclass']
    df_dict = schema_all_dict[columns_to_keep].set_index('name')
    data_from_xdm_full_schema = df_dict.to_dict()

    data_from_xdm_full_schema = df_dict.to_dict()
    xdm_rule_to_dtype = data_from_xdm_full_schema.get('datatype')
    xdm_rule_to_dclass = data_from_xdm_full_schema.get('dataclass')

    return xdm_rule_to_dtype, xdm_rule_to_dclass


def main():
    security_modeling_rules_path = "/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/Mapping for Defender For Cloud - One Data Model Migration.csv"
    if '.tsv' in security_modeling_rules_path:
        modeling_rules_df = pd.read_csv(security_modeling_rules_path, sep='\t')
    else:
        modeling_rules_df = pd.read_csv(security_modeling_rules_path)

    with open('/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/event.json', 'r') as f:
        raw_event = json.load(f)

    schema_path = "/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/Schema.csv"
    xdm_rule_to_dtype, xdm_rule_to_dclass = extract_data_from_all_xdm_schema(schema_path)

    name_columen = modeling_rules_df["Name"]
    xdm_one_data_model = modeling_rules_df["XDM Field One Data Model"]
    names_list = name_columen.to_numpy()
    xdm_one_data_model_list = xdm_one_data_model.to_numpy()

    mapping_list = []
    for (field_name, xdm_field_name) in zip(names_list, xdm_one_data_model_list):
        type_raw, is_array_raw = extract_raw_type_data(raw_event, field_name)
        xdm_field_type = xdm_rule_to_dtype.get(xdm_field_name)
        xdm_class_type = xdm_rule_to_dclass.get(xdm_field_name)

        mapping_list.append(MappingField(xdm_rule=xdm_field_name, field_path_raw=field_name,
                            xdm_field_type=xdm_field_type, xdm_class_type=xdm_class_type,
                            is_array_raw=is_array_raw, type_raw=type_raw))

    create_scheme_file(mapping_list)
    create_xif_file(mapping_list)
    create_yml_file()


if __name__ == '__main__':
    main()
