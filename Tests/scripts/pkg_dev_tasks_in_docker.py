#!/usr/bin/env python3
import argparse
import yaml
import glob
import subprocess
import os
import hashlib
import sys
import shutil

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
LOG_VERBOSE = False


def get_docker_image(script_obj):
    return script_obj.get('dockerimage') or DEF_DOCKER


def print_v(msg):
    if LOG_VERBOSE:
        print(msg)


def get_dev_requirements(project_dir, docker_image):
    """
    Get the requirements for the specified project. Will detect if python 2 or 3 is used and
    generate requirements file based on default required dev libs.

    Arguments:
        project_dir {string} -- Directory of the project
        docker_image {stiring} -- Docker image being used by the project

    Raises:
        ValueError -- If can't detect python version

    Returns:
        string -- requirement required for the project
    """
    stderr_out = None if LOG_VERBOSE else subprocess.DEVNULL
    major_ver = subprocess.check_output(["docker", "run", "--rm", docker_image,
                                         "python", "-c", "import sys; print(sys.version_info[0])"],
                                        universal_newlines=True, stderr=stderr_out).strip()
    print_v("detected python version: [{}] for docker image: {}".format(major_ver, docker_image))
    if major_ver not in ["2", "3"]:
        raise ValueError("Unknown python major versoin: {}".format(major_ver))
    env_dir = "{}{}".format(ENVS_DIRS_BASE, major_ver)
    requirements = subprocess.check_output(['pipenv', 'lock', '-r', '-d'], cwd=env_dir, universal_newlines=True,
                                           stderr=stderr_out)
    print_v("dev requirements:\n{}".format(requirements))
    return requirements


def get_pylint_files(project_dir):
    code_file = get_code_file(project_dir, '.py')
    return os.path.basename(code_file)


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
    target_image = 'devtest' + docker_base_image + '-' + hashlib.md5(requirements.encode('utf-8')).hexdigest()
    images_ls = subprocess.check_output(['docker', 'image', 'ls', '--format',
                                         '{{.Repository}}:{{.Tag}}', target_image], universal_newlines=True).strip()
    if images_ls == target_image:
        print('Using already existing docker image: {}'.format(target_image))
        return target_image
    print("Creating docker image: {} (this may take a minute or two...)".format(target_image))
    container_id = subprocess.check_output(
        ['docker', 'create', '-i', docker_base_image, 'sh', '/' + CONTAINER_SETUP_SCRIPT_NAME],
        universal_newlines=True).strip()
    subprocess.check_call(['docker', 'cp', CONTAINER_SETUP_SCRIPT, container_id + ':/' + CONTAINER_SETUP_SCRIPT_NAME])
    output = None if LOG_VERBOSE else subprocess.DEVNULL
    subprocess.run(['docker', 'start', '-a', '-i', container_id], input=requirements.encode('utf-8'), check=True,
                   stdout=output, stderr=output)
    subprocess.run(['docker', 'commit', container_id, target_image], check=True, stdout=output, stderr=output)
    subprocess.run(['docker', 'rm', container_id], check=True, stdout=output, stderr=output)
    print('Done creating docker image: {}'.format(target_image))
    return target_image


def docker_run(project_dir, docker_image, no_test, no_lint, keep_container):
    workdir = '/devwork'
    pylint_files = get_pylint_files(project_dir)
    # copy demistomock and common server
    shutil.copy(CONTENT_DIR + '/Tests/demistomock/demistomock.py', project_dir)
    open(project_dir + '/CommonServerUserPython.py', 'a').close()  # create empty file
    shutil.rmtree(project_dir + '/__pycache__', ignore_errors=True)
    subprocess.check_call(['python2', CONTENT_DIR + '/package_extractor.py', '-i',
                           'Scripts/script-CommonServerPython.yml', '-o',
                           project_dir + '/CommonServerPython.py'], cwd=CONTENT_DIR)
    run_params = ['docker', 'create', '-v', workdir, '-w', workdir,
                  '-e', 'PYLINT_FILES={}'.format(pylint_files)]
    if no_test:
        run_params.extend(['-e', 'PYTEST_SKIP=1'])
    if no_lint:
        run_params.extend(['-e', 'PYLINT_SKIP=1'])
    run_params.extend([docker_image, 'sh', './{}'.format(RUN_SH_FILE_NAME)])
    container_id = subprocess.check_output(run_params, universal_newlines=True).strip()
    try:
        subprocess.check_call(['docker', 'cp', project_dir + '/.', container_id + ':' + workdir])
        subprocess.check_call(['docker', 'cp', RUN_SH_FILE, container_id + ':' + workdir])
        subprocess.check_call(['docker', 'start', '-a', container_id])
    finally:
        if not keep_container:
            subprocess.check_output(['docker', 'rm', container_id])
        else:
            print("Test container [{}] was left available".format(container_id))


def main():
    description = """Run pylint and/or pytest within the docker image of an integration/script.
Meant to be used with integrations/scripts that use the folder (package) structure.
Will lookup up what docker image to use and will setup the dev dependencies and file in the target folder. """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--dir", help="Specify directory of integration/script", required=True)
    parser.add_argument("--no-lint", help="Do NOT lint (skip pylint)", action='store_true')
    parser.add_argument("--no-test", help="Do NOT test (skip pytest)", action='store_true')
    parser.add_argument("-k", "--keep-container", help="Keep the test container", action='store_true')
    parser.add_argument("-v", "--verbose", help="Verbose output", action='store_true')

    args = parser.parse_args()

    if args.no_test and args.no_lint:
        raise ValueError("Nothing to run as both --no-lint and --no-test specified.")

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
        print('Script is not of type "python". Found type: {}. Nothing to do.'.format(script_type))
        return 1
    docker = get_docker_image(script_obj)
    print_v("Using docker image: {}".format(docker))
    requirements = get_dev_requirements(project_dir, docker)
    docker_image_created = docker_image_create(docker, requirements)
    try:
        docker_run(project_dir, docker_image_created, args.no_test, args.no_lint, args.keep_container)
    except subprocess.CalledProcessError as ex:
        sys.stderr.write("[FAILED {}] Error: {}\n".format(project_dir, str(ex)))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
