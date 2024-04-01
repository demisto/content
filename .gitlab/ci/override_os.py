from demisto_sdk.commands.common.cpu_count import cpu_count
import os

# This will set the `os.cpu_count` to the `cpu_count` function, which is the real CPUs we use in the build
os.cpu_count = cpu_count
