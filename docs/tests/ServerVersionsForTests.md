### Server versions for Content tests

The CircleCI build tests run against 4 Server versions:
* Latest server master build
* Latest Server GA
* One GA version before latest server GA
* Two GA versions before latest server GA

The build will simultaneously create an AMI instance for each of the versions.\
The test set will only run on one machine at a time.\
The reason for this is that simultaneous runs of the same test, against the same real instance, might cause test failure.
This is because the instance changes states during the test. One test run might expect the instance to be in one state, while 
the other run caused the instance to change to a different state.

As a first stage for running against these four versions we will not run tests against the version - "Two GA versions before latest server GA" because it will cause us to do a lot of
fromversion additions to our TestPlaybooks. We plan to enable the run on this version once server version 4.5 will be released.

#### Build types

- Nightly - runs tests on all versions.
- Other - runs tests on latest Server GA.

**Note:** This process can be modified in the `create_instances.py` script located in Content repo.

#### Related files
| File | Repo |
| ------------- | ------------- |
| create_instances.py | https://github.com/demisto/content | 
