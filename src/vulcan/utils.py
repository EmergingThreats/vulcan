from typing import Union

import constants
import random
import uuid

def check_port(port: Union[str, int]):
    try:
        port_int = int(port)
        if 1 <= port_int <= 65535:
            return port_int
        else:
            raise ValueError(f"Invalid Port value ({port}). Valid range 1-65535.")
    except ValueError:
        if port == 'any' or port.startswith('$'):
            return random.choice(constants.TCP_PORTS.get(port.lower(), range(1024, 65535)))
        else:
            raise ValueError(f"Invalid Port Option ({port}). Valid options: any, 1-65535, $variable_ports")


def get_random_string(string_length=8):
    random = str(uuid.uuid4()) 
    random = random.upper()
    random = random.replace("-","")
    return random[0:string_length] 
