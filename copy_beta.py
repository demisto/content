import os
import shutil
import sys
path = sys.argv[1]
shutil.copyfile('beta-release-notes.md', os.path.join(path, 'beta-release-notes.md'))
