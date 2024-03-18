
import "pe"

rule EXE_Ransomware_Tuga_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects Tuga Ransomware Samples"
    file_hash = "79a4c04639a0a9983467370b38de262641da79ccd51a0cdcd53aba20158f1b3a"
    credits = "@suyog41 for sharing the malware file hash on Twitter"
    reference = "https://twitter.com/suyog41/status/1769614794703991255"
  
  strings:
    $tuga = "C:\\Users\\shade\\Downloads\\RansomTuga-master" 

  condition:
    (pe.version_info["InternalName"] == "RansomTuga.exe" 
    or pe.version_info["InternalName"] == "Tuga.exe" 
    or $tuga)
    and pe.number_of_sections == 7
    and pe.imports("KERNEL32.dll","AreFileApisANSI")
    and (pe.imports("ADVAPI32.dll","GetUserNameW")
    or pe.imports("USER32.dll","GetClipboardData"))
    
}

 

 
