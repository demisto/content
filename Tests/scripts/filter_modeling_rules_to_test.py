import typer
import json
from pathlib import Path
from packaging.version import Version
from collect_tests.logger import logger

def write_modeling_rules_to_text(artifacts_folder: str, output_file_name: str, modeling_rules: set[str]):
    modeling_rules_str = '\n'.join(modeling_rules)
    (Path(artifacts_folder) / Path(output_file_name)).write_text(modeling_rules_str)

def main(
    modeling_rules_to_test_file: str = typer.Option(help='A file that holds information about the modeling rules to test',
                                                    default='modeling_rules_to_test.json'),
    demisto_version: str = typer.Option(help='The version of the tenant that will run the modeling rules test',
                                      default='0.0.0'),
    artifacts_folder: str = typer.Option(help='The artifacts folder that will hold the filtered modeling rules', default='./')
    ):
    skipped_modeling_rules: set[str] = set()
    valid_modeling_rules_to_test: set[str] = set()
    modeling_rules: dict[str, dict[str, str]] = {}
    tenant_version: Version = Version(demisto_version)
    with Path(modeling_rules_to_test_file).open(encoding='utf-8') as modeling_rules_file:
        modeling_rules = json.loads(modeling_rules_file.read())
    for modeling_rule, versions in modeling_rules.items():
        # The 'from' key is mandatory, 'to' is optional
        fromVersion, toVersion = Version(versions['fromVersion']), Version(versions.get('toVersion', '99.99.99'))
        if tenant_version >= fromVersion and tenant_version <= toVersion:
            valid_modeling_rules_to_test.add(modeling_rule)
        else:
            skipped_modeling_rules.add(modeling_rule)
    # TODO Maybe log the skipped modeling rules?
    write_modeling_rules_to_text(
        artifacts_folder=artifacts_folder,
        output_file_name='valid_modeling_rules_to_test.txt',
        modeling_rules=valid_modeling_rules_to_test)
    # logger.debug(f'Will test {len(valid_modeling_rules_to_test)} modeling rules')

    write_modeling_rules_to_text(
        artifacts_folder=artifacts_folder,
        output_file_name='skipped_modeling_rules.txt',
        modeling_rules=skipped_modeling_rules)
    # logger.debug(f'Skipped {len(skipped_modeling_rules)} modeling rules')
    print(' '.join([f'Pack/{modeling_path}' for modeling_path in valid_modeling_rules_to_test]))
if __name__ in ('__main__'):
    try:
        typer.run(main)
    except Exception as e:
        logger.error(e)