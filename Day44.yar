import "vt"

rule New_C2_HookBot_Login_Panels
{
  meta:
    author = "RustyNoob"
    description = "Detects new URLs hosting the HookBot Andorid Malware C2 Login Panels"
    target_entity = "url"
  condition:
    vt.net.url.new_url and
    vt.net.url.html_title == "HOOKBOT PANEL"
}