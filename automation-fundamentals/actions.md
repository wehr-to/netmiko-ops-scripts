show version, show run > Does NOT change the device
send_config_set([...]) > DOES make device changes
write memory > DOES make device changes
reload, erase startup-config > DOES make device changes

# The device changes only when you do any of the following:

1: Send Configuration Commands
Using Netmiko, this looks like: conn.send_config_set(["hostname Switch1", "banner motd ^Authorized Access Only^"])

- Changes config in RAM (running-config)
- Takes effect immediately
- Doesn’t persist after reboot unless you run write mem or copy run start

2: Send Mode-Changing Commands
Commands like: 
conn.send_command("reload")
conn.send_command("erase startup-config")

These are dangerous because they:

- Trigger device reloads
- Wipe configs
- Force reboots

These should never be part of a script unless you’re absolutely sure what you're doing.

3: Write config to startup

conn.send_command("write memory")
# or
conn.send_command("copy run start")

This saves changes to flash so they persist after reboot. Without this, most changes are only temporary.

4: Enable Interfaces or Change VLANs
conn.send_config_set([
    "interface Gig0/1",
    "switchport access vlan 10",
    "no shutdown"
])

These change how the network actually behaves, you’re affecting traffic!






