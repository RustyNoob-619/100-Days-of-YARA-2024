# Please Read Me:

Ensure that the config.ini and the python script are in the same directory 

## Prerequisites

=> Requires the VirusTotal API key which is only accessible via the **Enterprise Subscription** (it might be worth getting the trial version)

=> An assumption is made that your YARA rules are stored in the same GitHub directory

## Config.ini 

Enter all the API values without the ""

 1. Enter Your API Key for VirusTotal 
 2. Enter the full path of your GitHub, this should be the raw content path and terminate just before the yara rule file 
 3. Enter the name of the YARA rule file with the extension (.yar or .yara), this should be exactly as the one on your GitHub
 4. Enter your email address for the notifcation of the validation check once it is completed 

### *Happy hunting* 🐧 
