#!/usr/bin/env python3

import logging



def get_logger(name: str = None, outfile: str = None, log_level: str = None) -> logging.Logger:
    """get_logger initializes console logger and file logger if outfile arg is passed
    
    Args:
        param1 (str): name 
        param2 (str): outfile

    Returns:
        logging.Logger Object

    """

    if not log_level:
        log_level = logging.getLevelName("WARNING")
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Log Formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler
    if outfile:
        fh = logging.FileHandler(outfile)
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    logging.getLogger("docker.utils.config").setLevel(logging.WARNING)
    
    return logger


def set_logger_fh(logger: object, outfile: str):
    """
    Initializes file logger for the passed logger object.

    :param logger: logger object;
    :param outfile: str;
    """

    log_level = logging.getLevelName("WARNING")

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    fh = logging.FileHandler(outfile)
    fh.setLevel(log_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
