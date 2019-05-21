import sys
import json
import requests
from pykwalify.core import Core

FILE_PATH = 'conf.json'
SCHEME_PATH = './Validators/conf_schema.yml'


def validate_duplicates():
    is_there_a_duplicate = False
    with open(FILE_PATH, 'r') as conf_file:
        conf_data = json.load(conf_file)

    integrations = conf_data.get('integrations')
    integrations_to_is_instance_name = {}
    for integration in integrations:
        integration_name = integration.get('name')
        integration_instance_name = integration.get('instance_name', '')
        if integration_name in integrations_to_is_instance_name.keys():
            if not integration_instance_name:
                is_there_a_duplicate = True
                existing_instances = '\n'.join(integrations_to_is_instance_name[integration_name])
                if not integrations_to_is_instance_name[integration_name][0]:
                    print("You've failed to add an instance name for the integration {} - please be advised "
                          "this is the not the first instance for this integration in "
                          "the conf.json, the other ones also don't contain instance_name, "
                          "so please add this field to all instances of this integration you can take a look at "
                          "Panorama as an example".format(integration_name))

                else:
                    print("You've failed to add an instance name for the integration {} - please be advised "
                          "this is the not the first instance for this integration in "
                          "the conf.json, the other ones are:\n{}".format(integration_name, existing_instances))
                continue

            if integration_instance_name in integrations_to_is_instance_name[integration_name]:
                is_there_a_duplicate = True
                print("You've added a second instance for the integration: {}"
                      "and with the same instance name {}".format(integration_name, integration_instance_name))
                continue

            integrations_to_is_instance_name[integration_name].append(integration_instance_name)

        else:
            integrations_to_is_instance_name[integration_name] = [integration_instance_name, ]

    if is_there_a_duplicate:
        sys.exit(1)


def get_id_set_json(circle_token):
    circle_data = requests.get(
        "https://circleci.com/api/v1/project/demisto/content/tree/master?limit=1&circle-token={}".format(circle_token))
    build_number = json.loads(circle_data.content)[0].get('build_num')

    artifacts = requests.get(
        "https://circleci.com/api/v1/project/demisto/content/{}/artifacts?circle-token={}".format(build_number,
                                                                                                  circle_token))
    all_artifacts = json.loads(artifacts.content)
    artifact_url = ""
    for artifact in all_artifacts:
        if "id_set.json" in artifact["path"]:
            artifact_url = artifact["url"]

    artifact = requests.get("{}?circle-token={}".format(artifact_url, circle_token))

    return json.loads(artifact.content)


def validate_with_content_repo(circle_token):
    has_probelmatic_instance_configuration = False

    id_set_json = get_id_set_json(circle_token)
    id_set_integrations = id_set_json['integrations']

    with open(FILE_PATH, 'r') as conf_file:
        conf_data = json.load(conf_file)

    integrations = conf_data.get('integrations')
    for integration in integrations:
        integration_name = integration.get('name')
        has_integration = integration.get('has_integration', True)
        is_server_integration = integration.get('is_server_integration', False)
        if is_server_integration:
            continue

        if not has_integration:
            continue

        found_match = False
        for id_set_integration in id_set_integrations:
            id_set_integration_name = id_set_integration.keys()[0]
            if id_set_integration_name == integration_name:
                found_match = True

        if not found_match:
            print("The integration {} doesn't appear in the id_set in conf.json file, thus you can't merge this "
                  "PR until you merge the one you intended to work on in content repo. You have the following options "
                  "\nYou can use this credentials by naming the branch in content repo and here in the same name.\n"
                  "You can add the 'has_integration=false' flag for the integration you added incase you just wanted "
                  "this info to be stored here\n".format(integration_name))
            has_probelmatic_instance_configuration = True

    if has_probelmatic_instance_configuration:
        sys.exit(1)


def main(argv):
    c = Core(source_file=FILE_PATH, schema_files=[SCHEME_PATH])
    try:
        c.validate(raise_exception=True)
    except Exception as err:
        print(err)
        print('Failed: %s failed' % (FILE_PATH,))
        sys.exit(1)

    validate_duplicates()
    if len(argv) == 1:
        validate_with_content_repo(argv[0])
    sys.exit(0)


if __name__ == "__main__":
    main([1084])
