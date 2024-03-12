import "vt"

rule Stealer_GlorySprout_C2_URLs
{
  meta:
    author = "RustyNoob619"
    description = "Detects URLs communicating with C2 Panels related to GlorySprout Stealer"
    target_entity = "url"
  condition:
    vt.net.url.new_url 
    and vt.net.url.downloaded_file.sha256 == "9d9429c76066202b412d8f78690529d3fb949813e74aaa8b35b445770323cb9a"
}
