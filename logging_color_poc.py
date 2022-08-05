import sys

if len(sys.argv) == 1:
    import logging
    from Tests.scripts.utils.log_util import install_logging
    install_logging('Destroy_instances.log')
else:
    from Tests.scripts.utils import logging_wrapper as logging
    from Tests.scripts.utils.log_util import install_logging
    install_logging('Destroy_instances.log', logger=logging)

logging.info(f'this is an info log: {sys.argv}')
logging.debug(f'this is a debug log')
logging.warning(f'this is a warning log')
logging.success(f'this is a success log')
