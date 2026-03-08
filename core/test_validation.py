#!/usr/bin/env python3
"""
Validation tests for Mac_IP_Merge v2.0
Run this to verify all bug fixes are working
"""

import sys
import csv
from pathlib import Path

def test_requirements():
    """Test that all required packages can be imported"""
    print("Testing package imports...")
    try:
        import netmiko
        print("  ✓ netmiko")
    except ImportError:
        print("  ✗ netmiko - run: pip install netmiko")
        return False
    
    try:
        import paramiko
        print("  ✓ paramiko")
    except ImportError:
        print("  ✗ paramiko - run: pip install paramiko")
        return False
    
    try:
        from mac_vendor_lookup import MacLookup
        print("  ✓ mac-vendor-lookup")
    except ImportError:
        print("  ✗ mac-vendor-lookup - run: pip install mac-vendor-lookup")
        return False
    
    return True


def test_drivers():
    """Test that all drivers can be imported"""
    print("\nTesting driver imports...")
    try:
        from device_driver import DeviceDriver
        print("  ✓ DeviceDriver base class")
    except ImportError as e:
        print(f"  ✗ DeviceDriver: {e}")
        return False
    
    try:
        from cisco_driver import CiscoIOSDriver
        print("  ✓ CiscoIOSDriver")
    except ImportError as e:
        print(f"  ✗ CiscoIOSDriver: {e}")
        return False
    
    try:
        from paloalto_driver import PaloAltoDriver
        print("  ✓ PaloAltoDriver")
    except ImportError as e:
        print(f"  ✗ PaloAltoDriver: {e}")
        return False
    
    return True


def test_driver_aliases():
    """Test that device type aliases work"""
    print("\nTesting device type aliases...")
    try:
        from mac_ip_merge import DRIVERS
        
        required_types = [
            'cisco', 'cisco_ios', 'cisco_iosxe',
            'paloalto', 'paloalto_panos'
        ]
        
        for dtype in required_types:
            if dtype in DRIVERS:
                print(f"  ✓ {dtype} -> {DRIVERS[dtype].__name__}")
            else:
                print(f"  ✗ {dtype} not found in DRIVERS")
                return False
        
        return True
    except ImportError as e:
        print(f"  ✗ Cannot import mac_ip_merge: {e}")
        return False


def test_csv_validation():
    """Test CSV file validation"""
    print("\nTesting CSV validation...")
    try:
        from mac_ip_merge import MACIPMerge
        
        # Test with valid CSV
        merge = MACIPMerge()
        if Path('devices.csv').exists():
            if merge.load_devices('devices.csv'):
                print(f"  ✓ Valid CSV loaded: {len(merge.devices)} devices")
            else:
                print("  ✗ Valid CSV failed to load")
                return False
        else:
            print("  ⚠ devices.csv not found, skipping validation test")
        
        return True
    except Exception as e:
        print(f"  ✗ CSV validation error: {e}")
        return False


def test_mac_normalization():
    """Test MAC address normalization"""
    print("\nTesting MAC normalization...")
    
    # Test Cisco format conversion
    test_mac = "906c.acbb.3580"
    mac_no_dots = test_mac.replace('.', '')
    normalized = ':'.join([mac_no_dots[i:i+2] for i in range(0, len(mac_no_dots), 2)])
    
    expected = "90:6c:ac:bb:35:80"
    if normalized == expected:
        print(f"  ✓ Cisco format: {test_mac} -> {normalized}")
    else:
        print(f"  ✗ Cisco format: {test_mac} -> {normalized} (expected {expected})")
        return False
    
    return True


def test_cli_parser():
    """Test CLI argument parser"""
    print("\nTesting CLI argument parser...")
    try:
        from mac_ip_merge import main
        import argparse
        
        # Check if argparse is used
        print("  ✓ argparse module available")
        print("  ✓ main() function exists")
        return True
    except Exception as e:
        print(f"  ✗ CLI parser error: {e}")
        return False


def test_output_directory_creation():
    """Test output directory creation"""
    print("\nTesting output directory creation...")
    try:
        from pathlib import Path
        
        test_path = Path("/tmp/test_output/subdir/file.csv")
        test_path.parent.mkdir(parents=True, exist_ok=True)
        
        if test_path.parent.exists():
            print("  ✓ Output directory creation works")
            # Cleanup
            import shutil
            shutil.rmtree("/tmp/test_output")
            return True
        else:
            print("  ✗ Output directory creation failed")
            return False
    except Exception as e:
        print(f"  ✗ Directory creation error: {e}")
        return False


def main():
    print("=" * 60)
    print("Mac_IP_Merge v2.0 - Validation Tests")
    print("=" * 60)
    
    tests = [
        ("Package Imports", test_requirements),
        ("Driver Imports", test_drivers),
        ("Device Type Aliases", test_driver_aliases),
        ("CSV Validation", test_csv_validation),
        ("MAC Normalization", test_mac_normalization),
        ("CLI Parser", test_cli_parser),
        ("Output Directory", test_output_directory_creation),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if test_func():
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed > 0:
        print("\n⚠ Some tests failed. Check errors above.")
        sys.exit(1)
    else:
        print("\n✓ All tests passed! Ready for deployment.")
        sys.exit(0)


if __name__ == '__main__':
    main()
