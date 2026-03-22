import importlib
import os
import sys
import types

# Ensure repository root is on sys.path so ip_helpers can be imported
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT_DIR)

# Provide a minimal yaml stub if PyYAML isn't installed
if 'yaml' not in sys.modules:
    yaml_stub = types.ModuleType('yaml')
    yaml_stub.safe_load = lambda stream: {}
    sys.modules['yaml'] = yaml_stub

ip_helpers = importlib.import_module('subnetting.utils.ip_helpers')


def test_convert_binary_ip_to_decimal_valid_binary():
    binary_ip = '11000000.10101000.00000001.00000001'
    assert ip_helpers.convert_binary_ip_to_decimal(binary_ip) == '192.168.1.1'


def test_convert_binary_ip_to_decimal_already_decimal():
    dec_ip = '10.1.1.1'
    assert ip_helpers.convert_binary_ip_to_decimal(dec_ip) == dec_ip


def test_convert_binary_ip_to_decimal_invalid_pattern():
    bad_binary = '11000000.10101000.00000001.0000000'  # last octet only 7 bits
    assert ip_helpers.convert_binary_ip_to_decimal(bad_binary) == bad_binary


def test_convert_binary_ip_to_decimal_invalid_type():
    assert ip_helpers.convert_binary_ip_to_decimal(None) == 'INVALID'


def test_validate_interface_name_valid_examples():
    assert ip_helpers.validate_interface_name('GigabitEthernet0/1')
    assert ip_helpers.validate_interface_name('FastEthernet1/0')
    assert ip_helpers.validate_interface_name('Ethernet0')
    assert ip_helpers.validate_interface_name('TenGigabitEthernet1/0/1')


def test_validate_interface_name_invalid_examples():
    assert not ip_helpers.validate_interface_name('GigabitEthernet')
    assert not ip_helpers.validate_interface_name('serial0/0')
    assert not ip_helpers.validate_interface_name('GigabitEthernet0/1a')
    assert not ip_helpers.validate_interface_name('')
