from Tests.test_utils import run_command


run_command('pwd', is_silenced=False)
run_command('find . -name "content_new.zip"', is_silenced=False)
run_command('unzip -o ./content_test.zip -d ./content_test', is_silenced=False)
run_command('zip -j ./content_new.zip ./content_test/*', is_silenced=False)
# run_command('rm -rf ./content_test', is_silenced=False)
