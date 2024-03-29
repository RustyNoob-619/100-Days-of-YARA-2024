
import "vt"

rule VT_APT_Transparent_Tribe
{
  meta:
    Author = "RustyNoob619"
    Description = "Potential malware attributed to Pakistan APT Transparent Tribe aka APT36"
    Credits = "@h2jazi for sharing the malware samples and the attribution"
    Reference = "https://twitter.com/h2jazi/status/1773468430013727186"
  
  condition:
    vt.metadata.imphash == "cb23e26cc45ed9aa58fdce155e7da31a"
    and vt.metadata.main_icon.dhash == "d89c988999a9b1b9"
}
