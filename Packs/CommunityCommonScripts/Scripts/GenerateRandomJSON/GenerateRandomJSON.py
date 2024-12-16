import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from faker import Faker
from datetime import datetime, date
from decimal import Decimal
import random


categories = {
    'IT': ['domain_name', 'email', 'ipv4', 'ipv6', 'url', 'user_name'],
    'Company': ['company', 'company_suffix', 'job', 'catch_phrase'],
    'Address': ['address', 'city', 'state', 'country', 'postalcode', 'street_address'],
    'Person': ['name', 'first_name', 'last_name', 'email', 'phone_number'],
    'Finance': ['credit_card_number', 'credit_card_provider', 'iban', 'bban'],
    'DateTime': ['date', 'time', 'year', 'month', 'date_of_birth'],
    'Profile': ['simple_profile'],
    'Color': ['color_name', 'hex_color', 'rgb_color', 'safe_color_name'],
    'Job': ['job', 'company', 'company_suffix', 'catch_phrase'],
    'Other': []
}

excluded_providers = ['get_providers', 'binary', 'zip', 'tar', 'json_bytes', 'get_words_list']

def serialize_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    elif isinstance(value, Decimal):
        return float(value)
    elif isinstance(value, (tuple, list)):
        return [serialize_value(v) for v in value]
    elif isinstance(value, dict):
        return {k: serialize_value(v) for k, v in value.items()}
    return value


def getAllValidProviders(faker):
    random_providers = [provider for provider in dir(faker) if not provider.startswith("_")]
    valid_providers_list: list = []
    for provider in random_providers:
        try:
            getattr(faker, provider)()
            if provider in excluded_providers:
                continue
            valid_providers_list.append(provider)
        except Exception:
            continue
    return valid_providers_list


def generate_fake_data(category: str, providers: List[str], num_entries: int, randomSize: int):
    global categories
    fake = Faker()
    fake_data_list = []
    providers_list = categories.get(category, [])

    if not isinstance(providers_list, list):
        raise TypeError(f"Expected a list for category '{category}', but got {type(providers_list).__name__}")

    all_valid_providers = getAllValidProviders(fake)

    if not isinstance(all_valid_providers, list):
        raise TypeError(f"Expected a list from getAllValidProviders, but got {type(all_valid_providers).__name__}")

    if category == 'Random':
        providers = random.sample(all_valid_providers, k=min(randomSize, len(all_valid_providers)))
    elif category != 'Other':
        if category not in list(categories.keys()):
            raise ValueError(f"Category '{category}' is not available. Choose from {list(categories.keys())}.")
        else:
            providers = random.sample(providers_list, k=min(10, len(providers_list)))
    else:
        # Check that all providers entered are valid
        missing_providers = [provider for provider in providers if provider not in all_valid_providers]
        if missing_providers:
            raise ValueError(f"Providers {missing_providers} are not valid faker providers.")

    for _ in range(num_entries):
        fake_data = {}
        for provider in providers:
            if hasattr(fake, provider):
                fake_data[provider] = serialize_value(getattr(fake, provider)())
            else:
                raise ValueError(f"Provider '{provider}' is not available in Faker.")
        fake_data_list.append(fake_data)

    return fake_data_list


def main():
    try:
        args = demisto.args()
        num_entries = int(args.get('list_size', 1))
        providers = argToList(args.get('faker_providers'))
        category = args.get('category', 'Random')
        random_size = int(args.get('dict_size', 10))

        if category == 'Other' and not providers:
            raise ValueError("When category is 'Other', a list of faker providers must be provided.")


        fake_data_list = generate_fake_data(category, providers, num_entries, random_size)

        return_results(CommandResults(
            readable_output=tableToMarkdown(f"Random JSON of category `{category}`", fake_data_list,
                                            headers=list(fake_data_list[0].keys())),
                                            outputs_prefix=f'RandomJSON.{category}',
                                            outputs=fake_data_list,
                                            raw_response=fake_data_list
                                            ))

    except Exception as ex:
        return_error(f"Failed to generate a Random JSON object.\nError: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
