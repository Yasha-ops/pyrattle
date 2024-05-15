import re
import os

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


from pyrattle.errors import BadArgument, FileNotPresent, ScanFailed, ScanParsingFailed

class ScanType(Enum):
    DEFAULT = 0
    QUICK  = 1
    FULL = 2
    CUSTOM = 3

@dataclass
class ScanResult():
     is_threat: bool = False
     threat: str = None
     ressources : int = 0
     file: str = None

class TraceGrouping(Enum):
    SERVICE = "0x1"
    MALWARE_PROTECTION_ENGINE =  "0x2"
    USER_INTERFACE="0x4"
    REAL_TIME_PROTECTION="0x8"
    SCHEDULED_ACTIONS="0x10" 
    WMI="0x20"
    NIS_GAPA="0x40"
    WINDOWS_SECURITY_CENTER="0x80"

class TraceLevel(Enum): 
    ERRORS: "0x1"
    WARNINGS:    "0X2"
    INFORMATIONAL_MESSAGES:  "0X4"    
    FUNCTION_CALLS:  "0X8"    
    VERBOSE:         "0X10"   
    PERFORMANCE:     "0X20"  

 
@dataclass
class PyDefender :
     executable_path: str = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
        
     def _run_command(self, args) -> Tuple[str, str, int]:
          command = [f'"{self.executable_path}"'] + args
          command_str = ' '.join(command)
          
          # Open pipes to capture stdout and stderr
          stdout_pipe = os.popen(f"{command_str} 2>&1")
          stdout = stdout_pipe.read()
          returncode = stdout_pipe.close()
      
          # In this simple example, stderr will be empty as it's redirected to stdout
          stderr = ""

          if returncode is None:
               returncode = 0

          return stdout, stderr, returncode

     
     def _parse_scan(self, output : str):
          threat = re.search(r"Threat\s+:\s*(.*)", output).group(1).strip()
          ressources = int(re.search(r"Resources\s+:\s*([0-9]+)\stotal", output).group(1))
          file = re.search(r"file\s*:(.*)", output).group(1).strip()

          return ScanResult(True, threat, ressources, file)


     def scan(self, scan_type : ScanType = ScanType.DEFAULT, file: str = None, disable_remediation: bool = False, boot_sector_scan : bool = False,  timeout : int = 30, is_cancel: bool = False) :
          """
          Perform a system scan based on the provided parameters.

          Parameters:
          ----------
          - scan_type : ScanType, optional
               The type of scan to perform. Default is ScanType.DEFAULT.
               Valid options:
               - ScanType.DEFAULT: According to your configuration.
               - ScanType.QUICK: Quick scan.
               - ScanType.FULL: Full system scan.
               - ScanType.CUSTOM: File and directory custom scan (requires `file` parameter).
          
          - file : `str`, `optional`
               The file or directory to be scanned. Required for `ScanType.CUSTOM`.
          
          - disable_remediation : `bool`, `optional`
               If True, disables remediation actions for custom scans.
               - File exclusions are ignored.
               - Archive files are scanned.
               - Actions are not applied after detection.
               - Event log entries are not written after detection.
               - Detections from the custom scan are not displayed in the user interface.
               - The console output will show the list of detections from the custom scan.
               Default is False.
          
          - boot_sector_scan : `bool`, `optional`
               If True, enables boot sector scanning. Only valid for custom scans.
               Default is False.
          
          - timeout : `int`, `optional`
               Timeout in days. Maximum value is 30. Default is 30 days for full scan and 1 day for all other scans.
               If not specified, default value is 7 days for full scan and 1 day for all other scans.
          
          - is_cancel : `bool`, `optional`
               If True, attempts to cancel any ongoing quick or full scan. Default is False.

          Raises:
          ------
          - FileNotPresent
               If `scan_type` is `ScanType.CUSTOM` and `file` is not provided.
          
          - ScanFailed
               If the scan fails (return code not 0 or 2).
          
          - ScanParsingFailed
               If there is an error parsing the scan results.

          Returns:
          -------
          - ScanResult
               The result of the scan, if successful.

          Example usage:
          --------------
          ```
               scan_result = scanner.scan(scan_type=ScanType.QUICK)
          ```
          """

          if (scan_type == ScanType.CUSTOM and file == None):
               raise FileNotPresent("When using Custom ScanType, a file or directory path should be provided")
          flags : List[str] = ["-Scan"]
          if (scan_type != ScanType.DEFAULT):
               flags.append(f"-ScanType {scan_type.value}")
          if (boot_sector_scan):
               flags.append("-BootSectorScan")
          if (timeout != 30):
               flags.append(f"-Timeout {timeout}")
          if (is_cancel):
               flags.append("-Cancel")
          if (disable_remediation):
               flags.append("-DisableRemediation")
          if (file):
               flags.append(f"-File {file}")
          
          stdout, stderr, returncode = self._run_command(flags)

          if (returncode != 0 and returncode != 2):
               raise ScanFailed
          
          if (returncode == 0): 
               # No threat found
               return ScanResult

          # Parsing  
          try:
               return self._parse_scan(stdout)
          except:
               raise ScanParsingFailed

     def updateSignature(self, unc: bool = False, unc_path: str = None, mmpc: bool = False) -> bool:
          """
          Updates the signature definitions for malware protection.

          This method checks for new definition updates and can perform updates from different sources:
          a UNC file share or directly from the Microsoft Malware Protection Center (MMPC).


          Parameters:
          ---
          - unc : `bool`
               If True, performs the update from a UNC file share. Default is False.
          - unc_path : `str`, `optional`
               The path to the UNC file share. Required if `unc` is True.
               If not specified and `unc` is True, the update will be performed
               from the preconfigured UNC location.
          - mmpc : `bool`
               If True, performs the update directly from the Microsoft Malware Protection Center (MMPC). Default is False.

          Returns:
          -------
          - `bool`:
               True if the update was successful (return code 0), False otherwise.
          """
          flags : List[str] = ["-SignatureUpdate"]

          if (unc) :
               flags.append("-UNC")
               if (unc_path):
                    flags.append(f"-Path {unc_path}")
          if (mmpc):
               flags.append("-MMPC")
          
          _, _, returncode = self._run_command(flags)

          return returncode == 0

     def addDynamicSignature(self, path: str) -> bool:
          """
          Adds a dynamic signature for malware protection from the specified path.

          This method allows you to add a dynamic signature, which can be used for
          custom or additional malware protection, by specifying the path to the
          signature file.

          Parameters:
          ---
          - path : `str`
               The path to the dynamic signature file. This argument is required.

          Raises:
          ---
          - FileNotFoundError: If the `path` is not provided.

          Returns:
          ---
          - `bool`:
               True if the dynamic signature was added successfully (return code 0), False otherwise.
          """
          if (path == None):
               raise FileNotFoundError("Path should be provided")
          flags : List[str] = ["-AddDynamicSignature", f"-Path {path}"]

          _, _, returncode = self._run_command(flags)

          return returncode == 0

     def _parse_signatures(self, output: str):
          return [line.split(": ")[1] for line in output.strip().split("\n")] 

     def listAllDynamicSignatures(self) -> List[str]:
          flags : List[str] = ['-ListAllDynamicSignatures']

          stdout, stderr , returncode = self._run_command(flags)

          if (returncode != 0 and returncode != 2):
               return []
          return self._parse_signatures(stdout)

     def removeDynamicSignature(self, signature_id: str) -> bool :
          if (signature_id == None):
               raise BadArgument

          flags : List[str] = ['-RemoveDynamicSignature', f"-SignatureSetID {signature_id}"]

          _, stderr , returncode = self._run_command(flags)

          return not (returncode != 0 and returncode != 2)
     
     def trace(self):
          # TODO
          pass
     
     def getfiles(self):
          # TODO
          pass
     
     def getfilesdiagtrack(self):
          # TODO
          pass

     def removedefinitions(self):
          # TODO
          pass

     def restore(self):
          # TODO
          pass
