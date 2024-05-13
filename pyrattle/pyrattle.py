from dataclasses import dataclass

from enum import Enum

class ScanType(Enum):
    DEFAULT = 0
    QUICK  = 1
    FULL = 2
    CUSTOM = 3

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
class PyRattle() :
    mpcmdrun_path: str = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"

    # -Scan
    scan_type : ScanType = ScanType.DEFAULT
    file: str = None
    is_boot_sector_scan : bool = False
    timeout : int = 30
    is_cancel: bool = False

    # -Trace
    grouping : TraceGrouping = None
    level: TraceLevel = None

    # -CaptureNetworkTrace
    captureNetworkTracePath: str = None

    # -GetFiles

    # -GetFilesDiagTrack

    # -AddDynamicSignature -Path 
    addDynamicSignaturePath: str = None

    # -ListAllDynamicSignatures
    
    # -RemoveDynamicSignature -SignatureSetID <SignatureSetID>
    signatureSetId: str = None

    # -CheckExclusion -path <path>
    checkExclusionPath : str = None

'''
   -Scan [-ScanType value]
      Return code is
      0    if no malware is found or malware is successfully remediated and no additional user action is required
      2    if malware is found and not remediated or additional user action is required to complete remediation or there is error in scanning.  Please check History for more information.

   -Trace [-Grouping value] [-Level value]

   -CaptureNetworkTrace -path <path>
       Captures all the network input into the Network Protection service and
       saves it to a file at <path>. Supply an empty path to stop tracing
       Note: The specified path must be writable by LocalService
       ex: C:\Users\Public\Downloads

   -GetFiles
        Gathers the following log files and packages them together in a
        compressed file in the support directory

        - Any trace files from Microsoft Antimalware Service
        - The Windows Update history log
        - All Microsoft Antimalware Service events from the System event log
        - All relevant Microsoft Antimalware Service registry locations
        - The log file of this tool
        - The log file of the signature update helper tool

   -GetFilesDiagTrack
        Same as GetFiles, but outputs the CAB file to the temp DiagTrack
        directory

   -RemoveDefinitions
        Restores the last set of signature definitions

        [-Engine]
        Restores the last saved engine
        Use this option to restore the previous engine.

        [-All]
        Removes any installed signature and engine files. Use this
        option if you have difficulties trying to update signatures.

        [-DynamicSignatures]
        Removes all Dynamic Signatures.

   -SignatureUpdate
        Checks for new definition updates

        [-UNC [-Path <path>]]
        Performs update directly from UNC file share specified in <path>
        If -Path is not specified, update will be performed directly from the
             preconfigured UNC location

        [-MMPC]
        Performs update directly from Microsoft Malware Protection Center

   -Restore
        [-ListAll]
        List all items that were quarantined

        [-Name <name>]
        Restores the most recently quarantined item based on threat name
        One Threat can map to more than one file

        [-All]
        Restores all the quarantined items based on name

        [-FilePath <filePath>]
        Restores quarantined item based on file path

        [-Path]
        Specify the path where the quarantined items will be restored.
        If not specified, the item will be restored to the original path.
   -AddDynamicSignature -Path <path>
        Adds a Dynamic Signature specified by <path>

   -ListAllDynamicSignatures
        Lists SignatureSet ID's of all Dynamic Signatures added to the client
        via MAPS and MPCMDRUN -AddDynamicSignature

   -RemoveDynamicSignature -SignatureSetID <SignatureSetID>
        Removes a Dynamic Signature specified by <SignatureSetID>

   -CheckExclusion -path <path>
        Checks whether <path> is excluded. It can be either a path, or a file.
'''
