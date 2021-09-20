import logging

LOGGING_LEVEL = logging.DEBUG

logging.basicConfig(
    level=LOGGING_LEVEL,
    format='%(asctime)s (%(funcName)s:%(lineno)d) - %(message)s'
)
