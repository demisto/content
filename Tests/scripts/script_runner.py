# This script should support python2
import subprocess
import os
import sys
import logging
import multiprocessing
def run_script(args, files):
    try:
        with multiprocessing.Pool() as pool:
            results = pool.map(lambda file: subprocess.run(args + [file], cwd=os.path.dirname(file)), files)
        
        if any(result.returncode != 0 for result in results):
            print("Script failed to run")
            return 1
    except subprocess.CalledProcessError as e:
        logging.error("Error: {e}".format(e=e))
    except Exception as e:
        logging.error("An error occurred: {e}".format(e=e))
    return 0
def main():
    args = sys.argv[1:]
    files_index = args.index("--files") if "--files" in args else -1
    script_args = args[:files_index]
    files = None
    if files_index != -1:
        files = args[files_index+1:]

    # Run the script
    return run_script(script_args, files)

if __name__ == "__main__":
    SystemExit(main())
