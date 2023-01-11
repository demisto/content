import pandas as pd 
import json

outputfile_schema = '/Users/okarkkatz/dev/demisto/content/Packs/AzureSecurityCenter/Integrations/ModelingRules/' + 'output.json'
outputfile_xif = '/Users/okarkkatz/dev/demisto/content/Packs/AzureSecurityCenter/Integrations/ModelingRules/' + 'output.xif'
VENDOR = "microsoft"
PRODUCT = "defender_for_cloud"
DATASET_NAME = f'{VENDOR.lower()}_{PRODUCT.lower()}_raw'


def create_xif_file(names : list , xdms : list):
    with open(outputfile_xif, 'w') as f: 
        f.write(f'[MODEL: dataset={DATASET_NAME}]\n')
        f.write('| alter\n')
        for (name, xdm) in zip (names, xdms):
            if not isinstance(xdm, str):
                xdm = None
            f.write(f'\t{xdm} = {name},\n')


def create_scheme_file(names_list : list, types_list : list):
    name_type_dict = {}
    for (name , field_type) in zip(names_list, types_list):
        if not isinstance(field_type, str):
            field_type = None
        name_type_dict[name] = {
            "type" : field_type,
            "is_array" : False,
        }
    modeling_rules_xif = {DATASET_NAME : name_type_dict}

    with open(outputfile_schema, 'w') as f: 
        res = json.dumps(modeling_rules_xif, indent=4)
        f.write(res)


def main():
    df = pd.read_csv("/Users/okarkkatz/dev/demisto/content/Packs/AzureSecurityCenter/Integrations/ModelingRules/Mapping for Defender For Cloud - One Data Model Migration.csv")

    name_columen=df["Name"]
    type_columen=df["Type"]
    XDM_one_data_model=df["XDM Field One Data Model"]
    names_list = name_columen.to_numpy()
    types_list = type_columen.to_numpy()
    XDM_one_data_model_list = XDM_one_data_model.to_numpy()

    create_scheme_file(names_list, types_list)
    create_xif_file(names_list, XDM_one_data_model_list)

if __name__ == '__main__':
    main()