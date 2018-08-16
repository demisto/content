import sys
from pykwalify.core import Core

def validate_file_release_notes(file_path):
    data_dictionary = None
    with open(file_path, "r") as f:
        if file_path.endswith(".json"):
            data_dictionary = json.load(f)
        elif file_path.endswith(".yaml") or file_path.endswith('.yml'):
            data_dictionary = yaml.safe_load(f)

    if data_dictionary and data_dictionary.get('releaseNotes') is None:
        print "File " + file_path + " is missing releaseNotes, please add."
        return False
    return True

def main(argv):
    if len(argv) < 2:
        print('you must provide file path & content-type')
        sys.exit(1)

    file_path = argv[0]
    schema_path = argv[1]
    
    ''' 
    This script runs both in a local and a remote environment. In a local environment we don't have any 
    logger assigned, and then pykwalify raises an error, since it is logging the validation results.
    Therefore, if we are in a local env, we set up a logger. Also, we set the logger's level to critical
    so the user won't be disturbed by non critical loggings
    '''
    is_local = False
    if len(argv) > 2:
        is_local = argv[2] and (argv[2] == True or argv[2].lower() == 'true')

    if is_local:
        import logging
        logging.basicConfig(level=logging.CRITICAL)

    check_release_notes = False
    if len(argv) > 3:
        check_release_notes = argv[3] and (argv[3] == True or argv[3].lower() == 'true')

    if check_release_notes:
        missing_release_notes = False
        if validate_release_notes:
            if not validate_file_release_notes(file_path):
                missing_release_notes = True

        if missing_release_notes:
            sys.exit(1)

    c = Core(source_file=file_path, schema_files=[schema_path])
    try:
        c.validate(raise_exception=True)
    except Exception as err:
        print 'Failed: %s failed' % (file_path,)
        print err
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
   main(sys.argv[1:])
