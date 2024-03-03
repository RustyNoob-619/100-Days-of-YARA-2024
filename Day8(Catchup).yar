import "pe"

rule TTP_Russian_Artifacts_Feb2024
{
   meta:
      author = "RustyNoob619"
      description = "Detects Russian Development Artifacts in the file"
   
   condition:
       for any resource in pe.resources:
       (resource.language == 1049) 
       or pe.locale(0x0419) // Russian (RU)

}
