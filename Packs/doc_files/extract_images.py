import os
import re


# def jason(file_path, image_details, pack_name, image_folder):
#     with open(file_path, 'r', encoding='utf-8') as f:
#         content = f.read()
#         images = re.findall(r'!\[(.*?)\]\((.*?)\)', content)
#         for image_alt, image_path in images:
#             if os.path.exists(image_path):
#                 # Copy image to doc_files folder
#                 image_name = os.path.basename(image_path)
#                 shutil.copy(image_path, os.path.join(image_folder, image_name))
#                 # Save image details to JSON
#                 image_details.append({
#                     'pack_name': pack_name,
#                     'file_location': file_path,
#                     'image_type': 'README' if 'README' in file_path else 'DESCRIPTION'
#                 })


def extract_image_link(text):
    # Regular expression to match URLs ending with common image file extensions
    image_link_pattern = r'\b\S+\.(png|jpg|jpeg|gif|bmp)\b'
    match = re.search(image_link_pattern, text, re.IGNORECASE)
    return match.group(0) if match is not None else None



def count_readme_and_description_files(folder_path, skip_folders=None, image_save_path=None):
    image_count = 0
    array_of_links = []
    if skip_folders is None:
        skip_folders = []

    # Path to save images
    if image_save_path is None:
        image_save_path = os.path.join(os.path.expanduser("~"), "dev", "demisto", "content", "Packs", "doc_files", "images")

    # Walk through all directories and files in the given folder path
    for root, dirs, files in os.walk(folder_path):
        # Exclude specified folders from the search
        dirs[:] = [d for d in dirs if d not in skip_folders]
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.lower() == "readme" or file_name.lower() == "description":
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    check = extract_image_link(content)
                    if check is not None:
                        array_of_links.append(check)
                # if os.path.isfile(file_path):
                #     with open(file_path, 'r', encoding='utf-8') as file:
                #         content = file.read()
                #         if re.search(r'\b(?:png|jpg|jpeg|gif|bmp)\b', content, re.IGNORECASE):
                #             image_count += 1
                #             if image_save_path:
                #                 # Create the directory if it doesn't exist
                #                 os.makedirs(image_save_path, exist_ok=True)
                #                 # Save the image
                #                 # shutil.copy(file_path, image_save_path)1

    return image_count


def main():
    folder_path = "/Users/mmorag/dev/demisto/content/Packs"
    skip_folders = ["ReleaseNotes", "TestPlaybooks", "venv"]
    image_save_path = "/Users/mmorag/dev/demisto/content/Packs/doc_files/images"
    image_count = count_readme_and_description_files(folder_path, skip_folders, image_save_path)
    print(f"Number of images link in our repo: {image_count}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
