
import "vt"

rule APT_Gamaredon_Infrastructure
{
  meta:
    author = "RustyNoob619"
    description = "Detects IP addresses attributed to Gamaredon APT based on JARM & SSL Certificate Properties"
    target_entity = "ip_address"
  condition:
    for any tag in vt.net.ip.tags:
    (tag == "self-signed")
    and vt.net.ip.jarm == "2ad2ad0002ad2ad22c2ad2ad2ad2adce7a321e4956e8298ba917e9f2c22849"
    and vt.net.ip.https_certificate.issuer.common_name == "Elastics" 
    and vt.net.ip.https_certificate.issuer.locality == "Kiyv"
    and vt.net.ip.https_certificate.issuer.organization == "Mordor"
    and vt.net.ip.https_certificate.issuer.country == "UA"
    and vt.net.ip.https_certificate.issuer.organizational_unit == "1"
    
}

