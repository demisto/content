import sys
from pykwalify.core import Core


def main(argv):
    if len(argv) < 2:
        print('you must provide file path & content-type')
        sys.exit(1)

    file_path = argv[0]
    schema_path = argv[1]
    # print ('starting ...')
    # print ('file_path - ' + file_path)
    c = Core(source_file=file_path, schema_files=[schema_path])
    try:
        c.validate(raise_exception=True)
    except Exception as err:
        print 'Failed: %s failed' % (file_path,)
        print err
        sys.exit(1)
    # print ('finished')
    sys.exit(0)


if __name__ == "__main__":
   main(sys.argv[1:])