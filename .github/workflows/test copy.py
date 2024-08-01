import os 

release='* added the `--force` flasg'

os.system("/Users/jbabazadeh/dev/demisto/content/.github/workflows/test.sh --body '" + release + "'")
