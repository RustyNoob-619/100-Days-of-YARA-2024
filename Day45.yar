import "vt"

rule C2_Mythic_SSL_Certs
{
  meta:
    author = "RustyNoob619"
    description = "Detects Mythic C2s based on the SSL Certificate Properties"
    target_entity = "ip_address"
  condition:
    for any tag in vt.net.ip.tags:
    (tag == "self-signed")
    and 
    (vt.net.ip.https_certificate.issuer.organization == "Mythic C2"
    or vt.net.ip.https_certificate.subject.organization == "Mythic C2")
}