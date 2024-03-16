
import "vt"

rule VT_RAT_Remcos_Mutex_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects Remcos RAT samples based on the Mutexes Created"
    file_hash = "6d22a23924808f2fa524a6ce98ee46ee6d34e1b02ce9605b4ff2d1ebdb1bc903"
    credits = "@BushidoToken for sharing the Remcos Mutex"
    reference = "https://twitter.com/BushidoToken/status/1768682487708815384"
  
  condition:
    vt.FileType.PE_EXE
    and for any mutex in vt.behaviour.mutexes_created:
    (mutex startswith "Rmc-")
}






 

 


 




 

 





 

 


 




 

 
