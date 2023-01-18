import pandas as pd
import json


def main():
    df = pd.read_csv(
        "/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/Schema.csv")

    # schema = df.to_dict('list')
    # name_columen = df["name"]
    # type_columen = df["dataclass"]

    # names_list = name_columen.to_numpy()
    # types_list = type_columen.to_numpy()

    columns_to_keep = ['name', 'datatype', 'dataclass']
    df_dict = df[columns_to_keep].set_index('name')
    df_dict = df_dict.to_dict()

    print('hellop')
    # array_type_fields = []
    # for (name, type) in zip(names_list, types_list):
    #     if type == 'Array':
    #         array_type_fields.append(name)

    # with open('/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/xdm_type.json', 'w') as f:
    #     json.dump(array_type_fields, f, indent=4)


if __name__ == '__main__':
    main()
