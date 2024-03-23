import "pe"

rule TTP_Chinese_Dropper_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects Exetutables which are written in the Chinese Simplified Language and contain an embedded DLL within them"
    file_hash = "c0721d7038ea7b1ba4db1d013ce0c1ee96106ebd74ce2862faa6dc0b4a97700d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
  
  condition:
    pe.number_of_resources == 1
    and for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload 
    
}




