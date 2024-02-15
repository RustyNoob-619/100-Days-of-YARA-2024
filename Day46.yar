import "vt"

rule Meduza_Stealer_Favicon
{
  meta:
    author = "RustyNoob619"
    description = "Detects Meduza Stealer based on the Favicon"
    target_entity = "url"
    sample_size = "163 URLs found on VT based on this Favicon"
  condition:
    vt.net.url.new_url and
    vt.net.url.favicon.raw_md5 == "e293a722fd181827b7ba8a2193beecae" 
    or vt.net.url.favicon.dhash == "69d49496f4711796"
}
