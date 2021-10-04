# Test filter mechanism

The most important thing you need to know is that we are running only the relevant set of tests for the changes you've made.
There are several things you should be aware of:
* We can automatically identify first layer connections between TestPlaybook and a script/integration/playbook. So if a TestPlaybook calls one of them it is automatically added to the list of the tests we are going to run.
* You can manually add a tests section in the yml file and state which tests you would like the build to run once you preform changes to that file. This section should be added in the last line of the yml file, and it should be in the global scope(no spaces from the start of the line). The names of the tests you put in there are the playbookIDs, the same as you put in the conf.json. A good example would be
```
tests:
  - Phishing test - attachment
  - Phishing test - Inline
```


* If you want to run all tests you should add the tests section and add `Run all tests` as a test you would like to run. 
* If you don't want to run tests for the file you just changed you should add the tests section
 and add `No test - <reason>` asa test you would like to run.
  Please make sure to write a reason, it is not a must but it would ease our lives. 
* Please take into consideration that both the automatic and the manual mechanisms are working side
 by side and don't override each other, and don't worry it will not cause the same test to run more than once. 
* Be ware if the both the automatic filter and the manual one don't find tests that should run for the current build 
it will fail the build with the message You've failed to provide tests for: <Test1>, <Test2> 

