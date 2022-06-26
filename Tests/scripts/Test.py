import logging
from Tests.scripts.utils.log_util import install_logging


def main():
    install_logging('Test_instances.log')
    logging.info("Info")
    logging.warning("Warning")
    logging.error("Error")

if __name__ == "__main__":
    main()
