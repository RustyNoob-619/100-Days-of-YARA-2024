import "vt"

rule Botnet_Mirai_C2
{
  meta:
    author = "RustyNoob619"
    description = "Detects URLs (domains and IPs) linked to the Mirai Botnet CnC"
    target_entity = "url"
  condition:
    vt.net.url.new_url
    and vt.net.url.downloaded_file.file_type == vt.FileType.HTML
    and (vt.net.url.downloaded_file.sha256 == "15b31cc80975c3e4c19dc9badf5a93d03c71de6dc8828f787bd1560478bdc1e3" 
    or vt.net.url.communicating_file.sha256 == "15b31cc80975c3e4c19dc9badf5a93d03c71de6dc8828f787bd1560478bdc1e3")
}
