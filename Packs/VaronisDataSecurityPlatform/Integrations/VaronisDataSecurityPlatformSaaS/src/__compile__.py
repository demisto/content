import os
import shutil


def merge_files(source_directory, file_list, output_file):
    """
    Merge multiple Python files into a single file.

    :param file_list: List of file paths to be merged.
    :param output_file: Path of the output file.
    """

    imports = set()
    module_names = [os.path.splitext(file_name)[0] for file_name in file_list]
    modules = dict()

    for file_path in file_list:
        current_module = os.path.splitext(file_path)[0]
        with open(f'{source_directory}/{file_path}', 'r') as file:
            module_code = []
            module_code.append(os.linesep)
            module_code.append(os.linesep)
            file_lines = file.readlines()
            for line in file_lines:
                if (line.startswith('import') or line.startswith('from')):
                    if line not in imports and not any(substring in line for substring in module_names):
                        imports.add(line)
                else:
                    module_code.append(line)
            modules[current_module] = ''.join(module_code)

    result_code = []
    result_code.append(''.join(imports))
    sorted_modules = sort_modules(list(modules.items()))
    for module_name, module_code in sorted_modules:
        result_code.append(modules[module_name])

    try:
        if os.path.exists(output_file):
            os.remove(output_file)
    except OSError as e:
        print(f"Error: {output_file} : {e.strerror}")

    with open(output_file, 'w') as file:
        file.writelines(''.join(result_code))
    print(f"Compiled file:{output_file}")


def build_graph(modules):
    graph = {}
    for module_name, _ in modules:
        graph[module_name] = []

    for module_name, module_code in modules:
        for other_module_name, _ in modules:
            if module_name != other_module_name and other_module_name in module_code:
                graph[module_name].append(other_module_name)

    return graph


def topological_sort(module_name, visited, stack, graph):
    visited[module_name] = True

    for neighbour in graph[module_name]:
        if not visited[neighbour]:
            topological_sort(neighbour, visited, stack, graph)

    stack.insert(0, module_name)


def sort_modules(modules):
    graph = build_graph(modules)
    visited = {mod_name: False for mod_name, _ in modules}
    stack = []

    for mod_name in visited:
        if not visited[mod_name]:
            topological_sort(mod_name, visited, stack, graph)

    sorted_modules = [(mod_name, next(mod_code for mod_name, mod_code in modules if mod_name == mod_name))
                      for mod_name in sorted(stack, reverse=False)]
    return sorted_modules


def get_source_files(current_directory):
    all_files_and_dirs = {f for f in os.listdir(current_directory)
                          if os.path.isfile(os.path.join(current_directory, f))}
    current_file = os.path.basename(__file__)

    source_files = {f for f in all_files_and_dirs
                    if os.path.isfile(os.path.join(current_directory, f)) and f.endswith('.py')
                    and not f.endswith(current_file)
                    and not f.endswith('CommonServerPython.py')
                    and not f.endswith('CommonServerUserPython.py')
                    and not f.endswith('conftest.py')
                    and not f.endswith('demistomock.py')
                    }

    files_to_copy = all_files_and_dirs - source_files - {current_file, current_file}

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


# Specify the output file name
source_directory = f'{os.getcwd()}/src/'
target_directory = f'{os.getcwd()}'
source_files, files_to_copy = get_source_files(source_directory)
print("Python files in the current directory:")
for file in source_files:
    print(file)
output_file_name = f'{target_directory}/VaronisDataSecurityPlatformSaaS.py'

merge_files(source_directory, source_files, output_file_name)
copy_files(files_to_copy, source_directory, target_directory)
