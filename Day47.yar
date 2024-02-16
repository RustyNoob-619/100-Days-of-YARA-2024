import "vt"

rule Stealer_RisePro_Login_Panels
{
  meta:
    author = "RustyNoob619"
    description = "Detects RisePRo C2 Login Panels based on Network Header properties"
    sample_size = "Matches on 242 URLs in Virus Total"
    target_entity = "url"
  condition:
    vt.net.url.new_url and
    vt.net.url.response_headers["Server"] == "RisePro"
}
