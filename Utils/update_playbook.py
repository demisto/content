import sys
import ntpath
import yaml
import yamlordereddictloader


def add_description(playbook):
    """
    add empty description to tasks of type title, start, end
    currently demisto exports those tasks without description, but the build hook validations require description

    :param playbook: playbook dict loaded from yaml
    :return: updated playbook dict
    """
    for task_id, task in playbook.get("tasks", {}).items():
        if task.get("type") in ["start", "end", "title"]:
            playbook["tasks"][task_id]["task"]["description"] = ""

    return playbook


def replace_version(playbook):
    """
    replace the version of playbook with -1

    :param playbook: playbook dict loaded from yaml
    :return: updated playbook dict
    """
    playbook["version"] = -1

    return playbook


def update_id_to_be_equal_name(playbook):
    """
    update the id of the playbook to be the same as playbook name
    the reason for that, demisto generates id - uuid for playbooks/scripts/integrations
    the conventions in the content, that the id and the name should be the same and human readable

    :param playbook: playbook dict loaded from yaml
    :return: updated playbook dict
    """
    playbook["id"] = playbook["name"]

    return playbook


def update_replace_copy_dev(playbook):
    """
    when developer clones playbook/integration/script it will automatically renamed to be _copy or _dev
    this function will replace _copy or _dev with empty string

    :param playbook: playbook dict loaded from yaml
    :return: updated playbook dict
    """
    playbook["name"] = playbook["name"].replace("_copy", "").replace("_dev", "")
    playbook["id"] = playbook["id"].replace("_copy", "").replace("_dev", "")

    for task_id, playbook_task in playbook.get("tasks", {}).items():
        inner_task = playbook_task.get("task", {})

        if "scriptName" in inner_task:
            playbook["tasks"][task_id]["task"]["scriptName"] = playbook["tasks"][task_id]["task"]["scriptName"]\
                .replace("_copy", "")\
                .replace("_dev", "")

        if "playbookName" in inner_task:
            playbook["tasks"][task_id]["task"]["playbookName"] = playbook["tasks"][task_id]["task"]["playbookName"]\
                .replace("_copy", "")\
                .replace("_dev", "")

        if "script" in inner_task:
            playbook["tasks"][task_id]["task"]["script"] = playbook["tasks"][task_id]["task"]["script"] \
                .replace("_copy", "") \
                .replace("_dev", "")

    return playbook


def update_playbook(source_path, destination_path):
    print "Starting..."

    with open(source_path) as f:
        playbook = yaml.load(f, Loader=yamlordereddictloader.Loader)

    playbook = update_replace_copy_dev(playbook)

    # add description to tasks that shouldn't have description like start, end, title
    playbook = add_description(playbook)

    # replace version to be -1
    playbook = replace_version(playbook)

    playbook = update_id_to_be_equal_name(playbook)

    if not destination_path:
        destination_path = ntpath.basename(source_path)

    if not destination_path.startswith("playbook-"):
        destination_path = "playbook-{}".format(destination_path)

    with open(destination_path, 'w') as f:
        yaml.dump(
            playbook,
            f,
            Dumper=yamlordereddictloader.Dumper,
            default_flow_style=False)

    print "Finished - new yml saved at {}".format(destination_path)


def main(argv):
    if len(argv) < 1:
        print "Please provide <source playbook path>, <optional - destination playbook path>"
        sys.exit(1)

    source_path = argv[0]
    destination_path = ""
    if len(argv) >= 2:
        destination_path = argv[1]

    update_playbook(source_path, destination_path)


if __name__ == "__main__":
    main(sys.argv[1:])
