import "vt"

rule TTP_Ransomware_Commands_Feb2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects PE Executables with suspicious commands leveraged by Ransomware"
    Credits = "@ShanHolo for sharing the thread on Twitter"
    Reference = "https://twitter.com/ShanHolo/status/1760262522345529803"
    target_entity = "file"
  
  condition:
    vt.metadata.new_file
    and vt.metadata.file_type == vt.FileType.PE_EXE
    and for any process in vt.behaviour.processes_created:
    (process == "C:\\Windows\\System32\\vssadmin.exe vssadmin  delete shadows /all /quiet"
    or process == "C:\\Windows\\System32\\wbem\\WMIC.exe wmic  shadowcopy delete"
    or process == "C:\\Windows\\System32\\wbadmin.exe wbadmin  delete catalog -quiet"
    or process == "C:\\Windows\\System32\\bcdedit.exe bcdedit  /set {default} recoveryenabled no"
    or process == "C:\\Windows\\System32\\bcdedit.exe bcdedit  /set {default} bootstatuspolicy ignoreallfailures"
    or process == "C:\\Windows\\System32\\wbadmin.exe wbadmin  delete systemstatebackup") 
    

}
