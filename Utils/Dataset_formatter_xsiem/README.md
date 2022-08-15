## README
The purpose of this script is to process exported datasets from XSIAM as lookup tables.

### pre requisite
In order to run this script you need to install the pandas module. 
Use ***pip install pandas***

### Assumptions
* All empty cells in date columns will be initialized with the date 2003-01-01T00:00:00
* All empty cells with json formats will be filled with the default empty list or dictionary [] or {}
* Windows paths or any backslash '\' in json format columns will turn to double '\\' 

### Example to run the script 
python dataset_formatter_xsiem.py -i 'Pulse_Secure - Pulse_Secure.csv'

### Script parameters 
usage: dataset_formatter_xsiem.py [-h] [-i INPUT] [-o OUTPUT] [-v]

A Script to format csv/tsv files in order to upload to XSIEM. This script is a work in progress and does not give a complete solution. if found a dataset that does not upload after running the script plz DM.

optional arguments:
##### -h, --help 
    show this help message and exit
##### -i, --input - Required
    Input file path (default: None)
##### -o, --output
    Output file path. If not specified the file will be saved in the folder the script was executed from (default: None)
##### -v, --verbose
    In order to view the columns modified by the script (default: False)
