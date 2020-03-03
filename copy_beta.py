import os
import shutil
import sys
path = sys.argv[1]
copy_to_path = os.path.join(path, 'beta-release-notes.md')
shutil.copyfile('beta-release-notes.md', copy_to_path)