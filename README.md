# Pyrattle

## Overview

Pyrattle is a Python package designed to interface with Windows Defender, enabling users to perform various malware protection tasks, such as scanning for threats, updating signature definitions, and managing dynamic signatures. It leverages Windows Defender's command-line utility (MpCmdRun.exe) to execute its functions.

## Features
- Perform different types of scans (Quick, Full, Custom)
- Update malware protection signatures from UNC file shares or the Microsoft Malware Protection Center (MMPC)
- Add, list, and remove dynamic signatures for enhanced malware protection
- Flexible configuration for scan options including remediation, boot sector scanning, and more

## Installation
```
pip install pyrattle
```

## Usage
Importing the Package


```
from pyrattle import PyDefender, ScanType
```

## Initializing PyDefender

```
scanner = PyDefender()
# or
scanner = PyDefender(executable_path="C:\\Program Files\\Windows Defender\\MpCmdRun.exe")
```

## Performing a Scan
It can perform multiple kinds of scan:
- **Quick Scan**
    ```
    scan_result = scanner.scan(scan_type=ScanType.QUICK)
    ```
- **Full Scan**
    ```
    scan_result = scanner.scan(scan_type=ScanType.FULL)
    ```

- **Custom Scan**
    ```
    scan_result = scanner.scan(scan_type=ScanType.CUSTOM)
    print(scan_result)
    ```

## Updating Signature Definitions
- **From UNC File Share**
    ```
    success = scanner.updateSignature(unc=True, unc_path="\\\\path\\to\\unc\\share")
    ```

- **From Microsoft Malware Protection Center**
    ```
    success = scanner.updateSignature(mmpc=True)
    ```

## Managing Dynamic Signature
- **Adding a Dynamic Signature**
    ```
    success = scanner.addDynamicSignature(path="C:\\path\\to\\signature\\file")
    print("Signature added successfully:", success)
    ```

- **Listing All Dynamic Signatures**
    ```
    signatures = scanner.listAllDynamicSignatures()
    print("Dynamic Signatures:", signatures)
    ```

- **Removing a Dynamic Signature**
    ```
    success = scanner.removeDynamicSignature(signature_id="signature_id")
    print("Signature removed successfully:", success)
    ```

## API Reference

### PyDefender

#### `scan(scan_type=ScanType.DEFAULT, file=None, disable_remediation=False, boot_sector_scan=False, timeout=30, is_cancel=False)`

Performs a system scan based on the provided parameters.

- **scan_type**: The type of scan to perform (`ScanType.DEFAULT`, `ScanType.QUICK`, `ScanType.FULL`, `ScanType.CUSTOM`).
- **file**: The file or directory to be scanned (required for `ScanType.CUSTOM`).
- **disable_remediation**: If `True`, disables remediation actions for custom scans.
- **boot_sector_scan**: If `True`, enables boot sector scanning (only valid for custom scans).
- **timeout**: Timeout in days (maximum value is 30).
- **is_cancel**: If `True`, attempts to cancel any ongoing quick or full scan.

Returns a `ScanResult` object if successful.

#### `updateSignature(unc=False, unc_path=None, mmpc=False)`

Updates the signature definitions for malware protection.

- **unc**: If `True`, performs the update from a UNC file share.
- **unc_path**: The path to the UNC file share (required if `unc` is `True`).
- **mmpc**: If `True`, performs the update directly from the MMPC.

Returns `True` if the update was successful, `False` otherwise.

#### `addDynamicSignature(path)`

Adds a dynamic signature for malware protection from the specified path.

- **path**: The path to the dynamic signature file.

Returns `True` if the dynamic signature was added successfully, `False` otherwise.

#### `listAllDynamicSignatures()`

Lists all dynamic signatures currently in use.

Returns a list of dynamic signatures.

#### `removeDynamicSignature(signature_id)`

Removes a dynamic signature based on the provided signature ID.

- **signature_id**: The ID of the signature to be removed.

Returns `True` if the signature was removed successfully, `False` otherwise.



## Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.

## License
This project is licensed under the MIT License.