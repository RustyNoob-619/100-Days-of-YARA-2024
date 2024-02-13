import "vt"

rule New_C2_HookBot_Login_Panels
{
  meta:
    author = "RustyNoob619"
    description = "Detects new URLs hosting the HookBot Andorid Malware C2 Login Panels"
    target_entity = "url"
  condition:
    vt.net.url.new_url and
    vt.net.url.html_title == "HOOKBOT PANEL" or 
    vt.net.url.html_title == "ERMVK" or
    vt.net.url.html_title == "ERMAC 3.0"
}
