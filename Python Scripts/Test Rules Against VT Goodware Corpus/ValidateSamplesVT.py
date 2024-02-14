from configparser import ConfigParser
import requests
import json

config = ConfigParser()
config.read("config.ini")
ini = config['Default']

rule_name = ini["rule-name"]
api_key = ini["API-KEY"]
git_url = ini["github-URL"] + rule_name
vt_email = ini["vt-email-address"]


def github_grab_yara_rule(raw_github_url):
    git_response = requests.get(url= raw_github_url)
    RuleSet = git_response.text
    return RuleSet

vt_url = "https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs"

vt_headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "x-apikey" : api_key 
}

def vt_test_yara_rule(vt_api_url, vt_api_headers, vt_notify_email ):
    yara_rule = github_grab_yara_rule(git_url)
    
    vt_input_parameters = { "data": {
            "type": "retrohunt_job",
            "attributes": {
                "rules": yara_rule,
                "corpus": "goodware",
                "notification_email": vt_notify_email
            }
        } }

    vt_request = requests.post(vt_api_url, json=vt_input_parameters, headers=vt_api_headers)

    vt_response = vt_request.json()
    id = vt_response["data"]["id"]
    return(print("Sucessful Rule Upload, here is your ID: ",id))


vt_test_yara_rule(vt_url, vt_headers, vt_email)
