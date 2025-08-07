# Connection handling (login, retries, etc.)

import time
from typing import Union, List, Tuple, Dict
from netmiko import (
    ConnectHandler,
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)


def connect_device_with_retries(
    device: Dict[str, str],
    commands: Union[str, List[str]] = "show version",
    retries: int = 3,
    delay: int = 2,
    config_commands: Union[None, str, List[str]] = None,
    debug: bool = False,
    return_conn: bool = False,
) -> Union[Tuple[str, str], ConnectHandler]:
    """
    Attempts to connect to a device with retries and send one or more commands.
    When ``return_conn`` is ``False`` (default) the function behaves as before
    and returns a tuple ``(device IP, output)``. If ``return_conn`` is ``True``
    a live ``ConnectHandler`` object is returned and the caller is responsible
    for closing the connection.
    """
    ip = device.get("host")
    attempt = 0

    if isinstance(commands, str):
        commands = [commands]

    if isinstance(config_commands, str):
        config_commands = [config_commands]

    while attempt < retries:
        try:
            if debug:
                print(f"[DEBUG] Attempting connection to {ip} (try {attempt + 1})")

            conn = ConnectHandler(**device)
            output = []

            for cmd in commands:
                output.append(conn.send_command(cmd))

            if config_commands:
                output.append(conn.send_config_set(config_commands))

            if return_conn:
                # Caller handles disconnect
                return conn

            conn.disconnect()
            return ip, "\n".join(output)

        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            if debug:
                print(f"[DEBUG] Connection error on {ip}: {str(e)}")
            attempt += 1
            if attempt >= retries:
                if return_conn:
                    raise
                return ip, f"Failed after {retries} attempts: {str(e)}"
            time.sleep(delay)
        except Exception as e:
            if debug:
                print(f"[DEBUG] Unhandled exception on {ip}: {str(e)}")
            if return_conn:
                raise
            return ip, f"Unhandled exception: {str(e)}"

    if return_conn:
        raise Exception("Unknown failure")
    return ip, "Unknown failure"

#1 - Function Inputs:

# device: dict containing Netmiko connection params (host, username, password, etc.)
# commands: CLI commands to retrieve output (can be string or list)
# config_commands: optional config commands (string or list)
# retries: max connection attempts
# delay: seconds between retries
# debug: print detailed logs for each attempt

#2 - Preprocess Inputs:

# Ensure commands and config_commands are lists

#3 - Retry Loop:

# Loop up to retries times:
# If debug=True, print attempt info
# Try SSH connect via ConnectHandler
# Run all commands using send_command()
# If config_commands provided, run via send_config_set()
# Disconnect and return output
# On timeout or auth errors, wait delay seconds and retry

#4 - Failure Handling:

# If all retries exhausted, return failure message
# Catch and log any other exceptions

# 5 - Return Output:

# Tuple: (host_ip, result_string) with either command output or failure reason










