#!/usr/bin/env python3
import argparse
import yaml
import glob
import subprocess
import os
import hashlib
import sys
import shutil
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/../..')
sys.path.append(CONTENT_DIR)
from package_creator import get_code_file  # noqa: E402

DEF_DOCKER = 'demisto/python:1.3-alpine'
ENVS_DIRS_BASE = '{}/dev_envs/default_python'.format(SCRIPT_DIR)
RUN_SH_FILE_NAME = 'run_dev_tasks.sh'
RUN_SH_FILE = '{}/{}'.format(SCRIPT_DIR, RUN_SH_FILE_NAME)
CONTAINER_SETUP_SCRIPT_NAME = 'pkg_dev_container_setup.sh'
CONTAINER_SETUP_SCRIPT = '{}/{}'.format(SCRIPT_DIR, CONTAINER_SETUP_SCRIPT_NAME)
RUN_MYPY_SCRIPT = '{}/run_mypy.sh'.format(SCRIPT_DIR)
LOG_VERBOSE = False
DOCKER_LOGIN_COMPLETED = False


def get_docker_images(script_obj):
    imgs = [script_obj.get('dockerimage') or DEF_DOCKER]
    alt_imgs = script_obj.get('alt_dockerimages')
    if alt_imgs:
        imgs.extend(alt_imgs)
    return imgs


def print_v(msg):
    if LOG_VERBOSE:
        print(msg)


def get_python_version(docker_image):
    """
    Get the python version of a docker image

    Arguments:
        docker_image {string} -- Docker image being used by the project

    Return:
        python version as a float (2.7, 3.7)

    Raises:
        ValueError -- if version is not supported
    """
    stderr_out = None if LOG_VERBOSE else subprocess.DEVNULL
    py_ver = subprocess.check_output(["docker", "run", "--rm", docker_image,
                                      "python", "-c",
                                      "import sys;print('{}.{}'.format(sys.version_info[0], sys.version_info[1]))"],
                                     universal_newlines=True, stderr=stderr_out).strip()
    print("Detected python version: [{}] for docker image: {}".format(py_ver, docker_image))
    py_num = float(py_ver)
    if py_num < 2.7 or (py_num > 3 and py_num < 3.4):  # pylint can only work on python 3.4 and up
        raise ValueError("Python vesion for docker image: {} is not supported: {}. "
                         "We only support python 2.7.* and python3 >= 3.4.".format(docker_image, py_num))
    return py_num


def get_pipenv_dir(py_version):
    """
    Get the direcotry holding pipenv files for the specified python version

    Arguments:
        py_version {float} -- python version as 2.7 or 3.7

    Returns:
        string -- full path to the pipenv dir
    """
    return "{}{}".format(ENVS_DIRS_BASE, int(py_version))


def get_dev_requirements(py_version):
    """
    Get the requirements for the specified py version.

    Arguments:
        py_version {float} -- python version as float (2.7, 3.7)

    Raises:
        ValueError -- If can't detect python version

    Returns:
        string -- requirement required for the project
    """
    env_dir = get_pipenv_dir(py_version)
    stderr_out = None if LOG_VERBOSE else subprocess.DEVNULL
    requirements = subprocess.check_output(['pipenv', 'lock', '-r', '-d'], cwd=env_dir, universal_newlines=True,
                                           stderr=stderr_out)
    print_v("dev requirements:\n{}".format(requirements))
    return requirements


def get_lint_files(project_dir):
    code_file = get_code_file(project_dir, '.py')
    return os.path.basename(code_file)


def docker_login():
    global DOCKER_LOGIN_COMPLETED
    if DOCKER_LOGIN_COMPLETED:
        return True
    docker_user = os.getenv('DOCKERHUB_USER', None)
    if not docker_user:
        print_v('DOCKERHUB_USER not set. Not trying to login to dockerhub')
        return False
    docker_pass = os.getenv('DOCKERHUB_PASSWORD', None)
    # pass is optional for local testing scenario. allowing password to be passed via stdin
    cmd = ['docker', 'login', '-u', docker_user]
    if docker_pass:
        cmd.append('--password-stdin')
    res = subprocess.run(cmd, input=docker_pass, capture_output=True, text=True)
    if res.returncode != 0:
        print("Failed docker login: {}".format(res.stderr))
        return False
    print_v("Completed docker login")
    DOCKER_LOGIN_COMPLETED = True
    return True


def docker_image_create(docker_base_image, requirements):
    """
    Create the docker image with dev dependencies. Will check if already existing.
    Uses a hash of the requirements to determine the image tag

    Arguments:
        docker_base_image {string} -- docker image to use as base for installing dev deps
        requirements {string} -- requirements doc

    Returns:
        string -- image name to use
    """

    if ':' not in docker_base_image:
        docker_base_image += ':latest'
    with open(CONTAINER_SETUP_SCRIPT, "rb") as f:
        setup_script_data = f.read()
    md5 = hashlib.md5(requirements.encode('utf-8') + setup_script_data).hexdigest()
    target_image = 'devtest' + docker_base_image + '-' + md5
    lock_file = ".lock-" + target_image.replace("/", "-")
    try:
        if (time.time() - os.path.getctime(lock_file)) > (60 * 5):
            print("{}: Deleting old lock file: {}".format(datetime.now(). lock_file))
            os.remove(lock_file)
    except Exception as ex:
        print_v("Failed check and delete for lock file: {}. Error: {}".format(lock_file, ex))
    wait_print = True
    for x in range(60):
        images_ls = subprocess.check_output(['docker', 'image', 'ls', '--format',
                                            '{{.Repository}}:{{.Tag}}', target_image], universal_newlines=True).strip()
        if images_ls == target_image:
            print('{}: Using already existing docker image: {}'.format(datetime.now(), target_image))
            return target_image
        if wait_print:
            print("{}: Existing image: {} not found will obtain lock file or wait for image".format(datetime.now(), target_image))
            wait_print = False
        print_v("Trying to obtain lock file: " + lock_file)
        try:
            f = open(lock_file, "x")
            f.close()
            print("{}: Obtained lock file: {}".format(datetime.now(), lock_file))
            break
        except Exception as ex:
            print_v("Failed getting lock. Will wait {}".format(str(ex)))
            time.sleep(5)
    try:
        # try doing a pull
        try:
            print("{}: Trying to pull image: {}".format(datetime.now(), target_image))
            pull_res = subprocess.check_output(['docker', 'pull', target_image],
                                               stderr=subprocess.STDOUT, universal_newlines=True)
            print("Pull succeeded with output: {}".format(pull_res))
            return target_image
        except subprocess.CalledProcessError as cpe:
            print_v("Failed docker pull (will create image) with status: {}. Output: {}".format(cpe.returncode, cpe.output))
        print("{}: Creating docker image: {} (this may take a minute or two...)".format(datetime.now(), target_image))
        container_id = subprocess.check_output(
            ['docker', 'create', '-i', docker_base_image, 'sh', '/' + CONTAINER_SETUP_SCRIPT_NAME],
            universal_newlines=True).strip()
        subprocess.check_call(['docker', 'cp', CONTAINER_SETUP_SCRIPT,
                               container_id + ':/' + CONTAINER_SETUP_SCRIPT_NAME])
        print_v(subprocess.check_output(['docker', 'start', '-a', '-i', container_id],
                                        input=requirements, stderr=subprocess.STDOUT,
                                        universal_newlines=True))
        print_v(subprocess.check_output(['docker', 'commit', container_id, target_image], stderr=subprocess.STDOUT,
                                        universal_newlines=True))
        print_v(subprocess.check_output(['docker', 'rm', container_id], stderr=subprocess.STDOUT,
                                        universal_newlines=True))
        if docker_login():
            print("{}: Pushing image: {} to docker hub".format(datetime.now(), target_image))
            print_v(subprocess.check_output(['docker', 'push', target_image], stderr=subprocess.STDOUT,
                                            universal_newlines=True))
    except subprocess.CalledProcessError as err:
        print("Failed executing command with  error: {} Output: \n{}".format(err, err.output))
        raise err
    finally:
        try:
            os.remove(lock_file)
        except Exception as ex:
            print("{}: Error removing file: {}".format(datetime.now(), ex))
    print('{}: Done creating docker image: {}'.format(datetime.now(), target_image))
    return target_image


def docker_run(project_dir, docker_image, no_test, no_lint, keep_container, use_root=False, cpu_num=0):
    workdir = '/devwork'  # this is setup in CONTAINER_SETUP_SCRIPT
    pylint_files = get_lint_files(project_dir)
    run_params = ['docker', 'create', '-w', workdir,
                  '-e', 'PYLINT_FILES={}'.format(pylint_files)]
    if not use_root:
        run_params.extend(['-u', '{}:4000'.format(os.getuid())])
    if no_test:
        run_params.extend(['-e', 'PYTEST_SKIP=1'])
    if no_lint:
        run_params.extend(['-e', 'PYLINT_SKIP=1'])
    run_params.extend(['-e', 'CPU_NUM={}'.format(cpu_num)])
    run_params.extend([docker_image, 'sh', './{}'.format(RUN_SH_FILE_NAME)])
    container_id = subprocess.check_output(run_params, universal_newlines=True).strip()
    try:
        print(subprocess.check_output(['docker', 'cp', project_dir + '/.', container_id + ':' + workdir],
                                      universal_newlines=True, stderr=subprocess.STDOUT))
        print(subprocess.check_output(['docker', 'cp', RUN_SH_FILE, container_id + ':' + workdir],
                                      universal_newlines=True, stderr=subprocess.STDOUT))
        print(subprocess.check_output(['docker', 'start', '-a', container_id],
                                      universal_newlines=True, stderr=subprocess.STDOUT))
    finally:
        if not keep_container:
            subprocess.check_output(['docker', 'rm', container_id])
        else:
            print("Test container [{}] was left available".format(container_id))


def run_flake8(project_dir, py_num):
    print("========= Running flake8 ===============")
    python_exe = 'python2' if py_num < 3 else 'python3'
    print_v('Using: {} to run flake8'.format(python_exe))
    sys.stdout.flush()
    subprocess.check_call([python_exe, '-m', 'flake8', project_dir], cwd=CONTENT_DIR)
    print("flake8 completed")


def run_mypy(project_dir, py_num):
    lint_files = get_lint_files(project_dir)
    print("========= Running mypy on: {} ===============".format(lint_files))
    sys.stdout.flush()
    subprocess.check_call(['bash', RUN_MYPY_SCRIPT, str(py_num), lint_files], cwd=project_dir)
    print("mypy completed")


def setup_dev_files(project_dir):
    # copy demistomock and common server
    shutil.copy(CONTENT_DIR + '/Tests/demistomock/demistomock.py', project_dir)
    open(project_dir + '/CommonServerUserPython.py', 'a').close()  # create empty file
    shutil.rmtree(project_dir + '/__pycache__', ignore_errors=True)
    shutil.copy(CONTENT_DIR + '/Tests/scripts/dev_envs/pytest/conftest.py', project_dir)
    if "/Scripts/CommonServerPython" not in project_dir:  # Otherwise we already have the CommonServerPython.py file
        shutil.copy(CONTENT_DIR + '/Scripts/CommonServerPython/CommonServerPython.py', project_dir)


def main():
    description = """Run lintings (flake8, mypy, pylint) and pytest. pylint and pytest will run within the docker image
of an integration/script.
Meant to be used with integrations/scripts that use the folder (package) structure.
Will lookup up what docker image to use and will setup the dev dependencies and file in the target folder. """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--dir", help="Specify directory of integration/script", required=True)
    parser.add_argument("--no-pylint", help="Do NOT run pylint linter", action='store_true')
    parser.add_argument("--no-mypy", help="Do NOT run mypy static type checking", action='store_true')
    parser.add_argument("--no-flake8", help="Do NOT run flake8 linter", action='store_true')
    parser.add_argument("--no-test", help="Do NOT test (skip pytest)", action='store_true')
    parser.add_argument("-r", "--root", help="Run pytest container with root user", action='store_true')
    parser.add_argument("-k", "--keep-container", help="Keep the test container", action='store_true')
    parser.add_argument("-v", "--verbose", help="Verbose output", action='store_true')
    parser.add_argument(
        "--cpu-num",
        help="Number of CPUs to run pytest on (can set to `auto` for automatic detection of the number of CPUs.)",
        default=0
    )

    args = parser.parse_args()

    if args.no_test and args.no_pylint and args.no_flake8 and args.no_mypy:
        raise ValueError("Nothing to run as all --no-* options specified.")

    global LOG_VERBOSE
    LOG_VERBOSE = args.verbose

    project_dir = os.path.abspath(args.dir)
    # load yaml
    yml_path = glob.glob(project_dir + '/*.yml')[0]
    print_v('Using yaml file: {}'.format(yml_path))
    with open(yml_path, 'r') as yml_file:
        yml_data = yaml.safe_load(yml_file)
    script_obj = yml_data
    if isinstance(script_obj.get('script'), dict):
        script_obj = script_obj.get('script')
    script_type = script_obj.get('type')
    if script_type != 'python':
        if script_type == 'powershell':
            # TODO powershell linting
            return 0
        print('Script is not of type "python". Found type: {}. Nothing to do.'.format(script_type))
        return 1
    dockers = get_docker_images(script_obj)
    for docker in dockers:
        for try_num in (1, 2):
            print_v("Using docker image: {}".format(docker))
            py_num = get_python_version(docker)
            setup_dev_files(project_dir)
            try:
                if not args.no_flake8:
                    run_flake8(project_dir, py_num)
                if not args.no_mypy:
                    run_mypy(project_dir, py_num)
                if not args.no_test or not args.no_pylint:
                    requirements = get_dev_requirements(py_num)
                    docker_image_created = docker_image_create(docker, requirements)
                    docker_run(
                        project_dir, docker_image_created, args.no_test,
                        args.no_pylint, args.keep_container, args.root, args.cpu_num
                    )
                break  # all is good no need to retry
            except subprocess.CalledProcessError as ex:
                sys.stderr.write("[FAILED {}] Error: {} Output: {}\n".format(project_dir, str(ex), ex.output))
                if not LOG_VERBOSE:
                    sys.stderr.write("Need a more detailed log?"
                                     " try running with the -v options as so: \n{} -v\n".format(" ".join(sys.argv[:])))
                # circle ci docker setup sometimes fails on
                if try_num > 1 or not ex.output or 'read: connection reset by peer' not in ex.output:
                    return 2
                else:
                    sys.stderr.write("Retrying as failure seems to be docker communication related...\n")
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
