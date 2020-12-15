import argparse

import demisto_client

from Tests.tools import update_server_configuration

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unlocks an integration, script or a playbook in Cortex XSOAR.")
    parser.add_argument("type", choices=["integration", "script", "playbook"])
    parser.add_argument("name")
    args = parser.parse_args()
    client = demisto_client.configure(verify_ssl=False)
    update_server_configuration(
        client,
        {f"content.unlock.{args.type}s": args.name},
        "Could not update configurations",
    )
    print(f"{args.type}: {args.name} unlocked.")
