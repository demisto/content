# Linting
As part of the build process we run a few linters to catch common programming errors. Linters are run only when working with the package (directory) structure. 

All linters are run via the following script:
```
./Tests/scripts/pkg_dev_test_tasks.py -h
usage: pkg_dev_test_tasks.py [-h] -d DIR [--no-pylint] [--no-mypy]
                             [--no-flake8] [--no-test] [-k] [-v]
                             [--cpu-num CPU_NUM]

Run lintings (flake8, mypy, pylint) and pytest. pylint and pytest will run
within the docker image of an integration/script. Meant to be used with
integrations/scripts that use the folder (package) structure. Will lookup up
what docker image to use and will setup the dev dependencies and file in the
target folder.

optional arguments:
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     Specify directory of integration/script (default:
                        None)
  --no-pylint           Do NOT run pylint linter (default: False)
  --no-mypy             Do NOT run mypy static type checking (default: False)
  --no-flake8           Do NOT run flake8 linter (default: False)
  --no-test             Do NOT test (skip pytest) (default: False)
  -k, --keep-container  Keep the test container (default: False)
  -v, --verbose         Verbose output (default: False)
  --cpu-num CPU_NUM     Number of CPUs to run pytest on (can set to `auto` for
                        automatic detection of the number of CPUs.) (default:
                        0)
```

**Note**: this script is also used to run pytest. See: [Unit Testing](../tests/unit-testing/README.md#run-with-docker)

## Flake8
This is a basic linter. It can be run without having all the dependencies available and will catch common errors. We also use this linter to enforce the standard python pep8 formatting style. On rare occasions you may encounter a need to disable an error/warning returned from this linter. Do this by adding an inline comment of the sort on the line you want to disable the error:
```python
#  noqa: <error-id>
```
For example:
```python
example = lambda: 'example'  # noqa: E731
```
When adding an inline comment always also include the error code you are disabling for. That way if there are other errors on the same line they will be reported.

More info: https://flake8.pycqa.org/en/latest/user/violations.html#in-line-ignoring-errors 


## Pylint
This linter is similar to flake8 but is able to catch some additional errors. We run this linter with error reporting only. It requires access to dependent modules and thus we run it within a docker image similar with all dependencies (similar to how we run pytest unit tests). On rare occasions you may encounter a need to disable an error/warning returned from this linter. Do this by adding an inline comment of the sort on the line you want to disable the error:
```
# pylint: disable=<error-name>
```
For example:
```python
a, b = ... # pylint: disable=unbalanced-tuple-unpacking
```
Is is also possible to `disable` and then `enable` a block of code. For example (taken from CommonServerPython.py):
```python
# pylint: disable=undefined-variable
if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str)
else:
    STRING_TYPES = (str, unicode)  # type: ignore
    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore
# pylint: enable=undefined-variable
```
**Note**: pylint can take both the error name and error code when doing inline comment disables. It is best to use the name which is clearer to understand. 

More info: https://pylint.readthedocs.io/en/latest/user_guide/message-control.html

For classes that generate members dynamically (such as goolgeapi classes) pylint will generate multiple `no-member` errors as it won't be able to detect the members of the class. In this case it is best to add a `.pylintrc` file which will include the following:
```
[TYPECHECK]

ignored-classes=<Class Name List>
```
See following example: https://github.com/demisto/content/blob/fe2bd5cddc6e521e08ef65fcd456a4214f8c4d93/Integrations/Gmail/.pylintrc

## Mypy
Mypy uses type annotations to check code for common errors. It contains type information for many popular libraries (via [typeshed project](https://github.com/python/typeshed)). Additionally, it allows you to define type annotations for your own functions and data structures. Type annotations are fully supported as a language feature in python 3.6 and above. In earlier versions type annotations are provided via the use of comments. 

We run mypy in a relatively aggressive mode so it type checks also functions which are don't contain type definitions. This may sometimes cause extra errors. If you receive errors you can always ignore the line with an inline comment of:
```python
# type: ignore
``` 
Dealing with ***Need type annotation errors***: If you receive such an error instead of simply adding an `ignore` comment it is better to define the type of the variable which is missing type annotation. This error is usually received when an empty dict or list is defined and mypy can not infer the type of the object. In this case it is better to define the type as `dict` or `list`. For example python 2 code:
```python
my_list = []  # type: list
```
Or with python 3 annotations
```
my_list: list = []
```
If you know the type that the list will hold use the type constructor `List` that can specify also what type it holds. For example a list which we know that will hold strings in python 2 code:
```python
my_list = []  # type: List[str]
```
Or with python 3 annotations
```python
my_list: List[str] = []
```
**Note:** When using type constructors such as `List` or `Dict` there is need to import the type from the typing module in python 3. In python 2 as part of running mypy our wrapper script will include the typing module.

More info at: https://mypy.readthedocs.io/en/latest/index.html
