from configparser import ConfigParser
from stix2 import Relationship, Indicator, Malware, MemoryStore

#Intialisations
mem = MemoryStore()  # Local memory store holding the STIX bundle 
config = ConfigParser()
config.read("config.ini")
ini = config['Default']

malware_name = ini['malware_name']
yara_file = ini['yara_rules_file']

#Input YARA File
yara_rule_file = open(yara_file, "r")
yara_rule = yara_rule_file.read()
yara_rule_file.close()

yara_rule_file = open(yara_file, "r")
for line in yara_rule_file.readlines():
    if line.startswith("rule") == True:
        split1 = line.split() 
        yara_rule_name = split1[1]
        
    if line.lstrip().startswith("description") == True:
        split2 = line.split("\"") 
        yara_rule_description = split2[1]  
yara_rule_file.close()

yara = Indicator(
            name = yara_rule_name,
            description = yara_rule_description,
            indicator_types = "malicious-activity",
            pattern_type = "yara",
            pattern = yara_rule)

malware = Malware(name=malware_name, is_family=False)

yara_relationship_malware = Relationship(relationship_type='indicates',
                                      source_ref=yara.id,
                                      target_ref=malware.id)

#Generate STIX 
mem.add([yara, malware, yara_relationship_malware])
mem.save_to_file("YARA_Result.json")  # Saving to JSON, generates a STIX bundle for YARA rule that detects a malware





