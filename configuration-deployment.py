# Backup running-config to local storage / Cisco specific script
# Output creates a backups/ folder if it does not already exist, the output itself is saved along the lines of "R1_running-config_20240520-230133.txt"

from netmiko import ConnectHandler
from datetime import datetime
import os

device = {
    "device_type": "cisco_ios",
    "ip": "192.168.1.1",
    "username": "admin",
    "password": "cisco123",
}

def backup_running_config(device):
    try:
        connection = ConnectHandler(**device)
        hostname = connection.find_prompt().strip("#>")

        print(f"Connected to {hostname} ({device['ip']})")

        output = connection.send_command("show running-config")

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{hostname}_running-config_{timestamp}.txt"

        os.makedirs("backups", exist_ok=True)

        with open(f"backups/{filename}", "w") as file:
            file.write(output)

        print(f"Config saved as backups/{filename}")
        connection.disconnect()

    except Exception as e:
        print(f"Failed to back up {device['ip']}: {e}")

if __name__ == "__main__":
    backup_running_config(device)


