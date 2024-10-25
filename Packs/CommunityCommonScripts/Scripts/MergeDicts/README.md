This transformer will merge 2 dicts using {**dict1, **dict2}. The result is saved in key "MergedDicts".

Example: !MergeDicts value=${DBotScore} dictionary=${InfoFile} overwrite=true