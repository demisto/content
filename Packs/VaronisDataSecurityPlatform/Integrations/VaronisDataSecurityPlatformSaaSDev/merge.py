import os
import shutil


def merge_files(file_list, output_file):
    """
    Merge multiple Python files into a single file.

    :param file_list: List of file paths to be merged.
    :param output_file: Path of the output file.
    """
    all_lines = []
    imports = set()

    classes = [os.path.splitext(f)[0] for f in file_list]
    merged_content = dict()
    
    for file_path in file_list:
        cur_class = os.path.splitext(file_path)[0]
        with open(file_path, 'r') as file:
            actual_lines = []
            lines = file.readlines()
            actual_lines.append('\r\n')
            actual_lines.append('\r\n')
            for line in lines:
                # Check for import statements
                if (line.startswith('import') or line.startswith('from')):
                    if line not in imports and not any(substring in line for substring in classes):
                        imports.add(line)
                        #actual_lines.append(line)
                else:
                    actual_lines.append(line)
            merged_content[cur_class] = ''.join(actual_lines)

    

    new_all_lines = []
    new_all_lines.append(''.join(imports))
    sorted_modules = sort_modules(list(merged_content.items()))
    for mod_name, mod_code in sorted_modules:
        new_all_lines.append(merged_content[mod_name])
    
    with open(output_file, 'w') as file:
        file.writelines(''.join(new_all_lines))
    print(f"Merged files into {output_file}")

def build_graph(modules):
    graph = {}
    for mod_name, _ in modules:
        graph[mod_name] = []

    for mod_name, mod_code in modules:
        for other_mod_name, _ in modules:
            if mod_name != other_mod_name and other_mod_name in mod_code:
                graph[other_mod_name].append(mod_name)

    return graph

def topological_sort_util(mod_name, visited, stack, graph):
    visited[mod_name] = True

    for neighbour in graph[mod_name]:
        if not visited[neighbour]:
            topological_sort_util(neighbour, visited, stack, graph)

    stack.insert(0, mod_name)

def sort_modules(modules):
    graph = build_graph(modules)
    visited = {mod_name: False for mod_name, _ in modules}
    stack = []

    for mod_name in visited:
        if not visited[mod_name]:
            topological_sort_util(mod_name, visited, stack, graph)

    sorted_modules = [(mod_name, next(mod_code for mod_name, mod_code in modules if mod_name == mod_name)) for mod_name in stack]
    return sorted_modules

import os

def list_python_files_in_current_directory():
    # Get the current working directory
    current_directory = os.getcwd()
    
    # List all files and directories in the current directory
    all_files_and_dirs = { f for f in os.listdir(current_directory)
                          if os.path.isfile(os.path.join(current_directory, f))}

    # Filter out directories and non-Python files, keep only Python files
    source_files = {f for f in all_files_and_dirs 
                    if os.path.isfile(os.path.join(current_directory, f)) and f.endswith('.py')
                        and not f.endswith('merge.py')
                        and not f.endswith('CommonServerPython.py')
                        and not f.endswith('CommonServerUserPython.py')
                        and not f.endswith('conftest.py')
                        and not f.endswith('demistomock.py')
                        and not f.endswith('_test.py')
                        }
    
    files_to_copy = all_files_and_dirs - source_files - {'merged', 'merge.py'}

    return source_files, files_to_copy

def copy_files(file_list, source_dir, target_dir):
    """
    Copy a list of files from a source directory to a target directory.

    :param file_list: List of filenames to copy.
    :param source_dir: Directory where the files are currently located.
    :param target_dir: Directory where the files should be copied to.
    """
    for file_name in file_list:
        source_path = os.path.join(source_dir, file_name)
        target_path = os.path.join(target_dir, file_name)

        # Check if file exists in source directory
        if os.path.isfile(source_path):
            shutil.copy(source_path, target_path)
            print(f"Copied {file_name} to {target_dir}")
        else:
            print(f"File not found: {source_path}")

def delete_all_in_directory(directory):
    """
    Delete all files and folders in the specified directory.

    :param directory: Path of the directory to clear.
    """
    # Check if the directory exists
    if not os.path.exists(directory):
        print(f"The directory {directory} does not exist.")
        return

    # Loop through all items in the directory
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)

        # Check if it's a file or folder
        if os.path.isfile(item_path):
            os.remove(item_path)  # Remove file
        elif os.path.isdir(item_path):
            shutil.rmtree(item_path)  # Remove directory

        print(f"Deleted {item}")

# Call the function and print the list of Python files
source_files, files_to_copy = list_python_files_in_current_directory()
print("Python files in the current directory:")
for file in source_files:
    print(file)


# Specify the output file name
source_directory = current_directory = os.getcwd()
target_directory = 'publish'
if not os.path.exists(target_directory):
    # If it doesn't exist, create it
    os.makedirs(target_directory)

output_file_name = f'{target_directory}/VaronisDataSecurityPlatformSaaS.py'

delete_all_in_directory(target_directory)
merge_files(source_files, output_file_name)
copy_files(files_to_copy, source_directory, target_directory)
