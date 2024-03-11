
import "pe"

rule EXE_Stealer_Planet_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects Planet Stealer malware"
    Source = "https://inquest.net/blog/around-we-go-planet-stealer-emerges/"
    File_Hash = "e846d3cfad85b09f8fdb0460fff53cfda1176f4e9e420bf60ed88d39b1ef93db"

  strings:
    $go = "Go buildinf:"
    $hex = {504534746952}

  condition:
    pe.imphash() == "9aebf3da4677af9275c461261e5abde3"
    and pe.number_of_sections == 3
    and pe.sections[0].name == "UPX0"
    and $go
    and $hex
    and filesize > 4MB and filesize < 5MB
}





 

 
