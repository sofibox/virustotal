````
virustotal --version
=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=

Info: VirusTotal (virustotal) is  bash script using VirusTotal API with an IP address lookup
performs automated searches of IP addresses against the VirusTotal database to check for potential security threats and reputation information

Version: 0.1-beta

Author: Arafat Ali | Email: arafat@sofibox.com | (C) 2019-2023

=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=
````

This bash script is used to check if an IP or domain is on a blacklist by utilizing the API from [VirusTotal](https://www.virustotal.com/).

# Setup:

Download [maxibuild](https://github.com/sofibox/maxibuild) and run the following command to install it in your system (recommended for maintainability)

`maxibuild --install virustotal --force`

or 

You can also clone this repository and run virustotal directly from the repository folder.

```
git clone https://github.com/sofibox/virustotal.git
cd virustotal
chmod +x virustotal
./virustotal --version
````

# Script configuration:

````
You can insert your API key in the script by editing the config file virustotal.conf. The script will also prompt you to enter your API key if you did not insert it in the config file.

You can limit the script check IP output by editing the variable VIRUSTOTAL_OUTPUT_MAX_LIMIT from the config file virustotal.conf. Default value is 500. If the IP address has more than 500 records, the script will delete the oldest records to make sure the output is not more than 500 records.

````

# Script usage:

````
virustotal <+ action> <* options>, where + is required and * is optional
````

# Script documentation

List of available actions:

`check` or `scan`

````
        This action is use to query the virustotal.com API. Required option is --target or --ip-address

        example:
            ./virustotal check --ip 1.2.3.4
            ./virustotal check --ip-address 1.2.3.4
            ./virustotal check --domain sofibox.com
            ./virustotal check --domain-name sofibox.com
            ./virustotal check --target 1.2.3.4
            
            
        short version:
            ./virustotal check -t warez-bb.org
            
            Note: VirusTotal does not support IPv6 yet. If an IPv6 address is used or a domain is resolved to IPv6 address, the script will return an error from API.
            
            
        output:
            [virustotal->info]: Checking target IP address 103.224.182.238 ...
            Virustotal scan results [new]:
            -------------
            Target: warez-bb.org
            IP address: 103.224.182.238
            AS owner: Trellian Pty. Limited
            Harmless: 75
            Malicious: 1
            Suspicious: 0
            Undetected: 12
            Timeout: 0
            Result: malicious
            Last scan date: Tue Jan 31 08:33:10 +08 2023
            -------------
       Note 1: The output above does not contain all the information returned by the API. You can view the full output by using the --json option.
       Note 2: The value for Result when using without --json option is calculated based on the following formula:
      
            if [[ ${malicious} -eq 0 && ${suspicious} -eq 0 && ${harmless} -gt 0 ]]; then
              result="clean"
            elif [[ ${malicious} -eq 0 && ${suspicious} -gt 0 ]]; then
              result="suspicious"
            elif [[ ${malicious} -gt 0 ]]; then
              result="malicious"
            else
              result="unknown"
            fi
            
````

Other optional options:
````
-h, --help
    This option is use to display the help message for the script
    
-v, --verbose
    This option is use to enable verbose output. You can use this option multiple times to increase the verbosity level (eg: -vvv)
    
    eg:
        ./virustotal check --ip-address 1.2.3.4 --verbose or ./virustotal check --ip-address 1.2.3.4 -v
    
-s, --scripting
    This option is use to enable scripting mode. When this option is enabled, you can the get a script status code or print the short result
   
    eg: 
        ./virustotal check -t 191.15.138.10 --scripting; echo $?
        malicious
        2
        
        Note: The return value above is malicious (with return code 2). It means the target IP address is malicious. The complete list of return codes are as follow:
         
         clean - (return 0), suspicious (return 1), malicious (return 2), unknown (return 3).  

-j, --json
    This option is use to enable json output. When this option is enabled, the script will output the result in json format. 
    
    eg:
        ./virustotal check --ip-address 1.2.3.4 --json
        
    output (sample):
    
            [virustotal->info]: Checking target IP address 1.2.3.4 ...
            Virustotal scan results [new]:
            -------------
            {
              "data": {
                "attributes": {
                  "whois": "inetnum: 1.2.3.0 - 1.2.3.255\nnetname: Debogon-prefix\ndescr: APNIC Debogon Project\ndescr: APNIC Pty Ltd\ncountry: AU\norg: ORG-RQA1-AP\nadmin-c: AR302-AP\ntech-c: AR302-AP\nabuse-c: AA1412-AP\nstatus: ASSIGNED PORTABLE\nmnt-by: APNIC-HM\nmnt-routes: MAINT-AU-APNIC-GM85-AP\nmnt-irt: IRT-APNICRANDNET-AU\nlast-modified: 2020-11-25T06:34:44Z\nsource: APNIC\nirt: IRT-APNICRANDNET-AU\naddress: PO Box 3646\naddress: South Brisbane, QLD 4101\naddress: Australia\ne-mail: helpdesk@apnic.net\nabuse-mailbox: helpdesk@apnic.net\nadmin-c: AR302-AP\ntech-c: AR302-AP\nauth: # Filtered\nremarks: helpdesk@apnic.net was validated on 2021-02-09\nmnt-by: MAINT-AU-APNIC-GM85-AP\nlast-modified: 2021-03-09T01:10:21Z\nsource: APNIC\norganisation: ORG-RQA1-AP\norg-name: Resource Quality Assurance\ncountry: AU\naddress: 6 Cordelia Street, South Brisbane\ne-mail: research@apnic.net\nmnt-ref: APNIC-HM\nmnt-by: APNIC-HM\nlast-modified: 2020-11-25T05:35:30Z\nsource: APNIC\nrole: ABUSE APNICRANDNETAU\naddress: PO Box 3646\naddress: South Brisbane, QLD 4101\naddress: Australia\ncountry: ZZ\nphone: +000000000\ne-mail: helpdesk@apnic.net\nadmin-c: AR302-AP\ntech-c: AR302-AP\nnic-hdl: AA1412-AP\nremarks: Generated from irt object IRT-APNICRANDNET-AU\nabuse-mailbox: helpdesk@apnic.net\nmnt-by: APNIC-ABUSE\nlast-modified: 2021-03-09T01:10:22Z\nsource: APNIC\nrole: APNIC RESEARCH\naddress: PO Box 3646\naddress: South Brisbane, QLD 4101\naddress: Australia\ncountry: AU\nphone: +61-7-3858-3188\nfax-no: +61-7-3858-3199\ne-mail: research@apnic.net\nnic-hdl: AR302-AP\ntech-c: AH256-AP\nadmin-c: AH256-AP\nmnt-by: MAINT-APNIC-AP\nlast-modified: 2018-04-04T04:26:04Z\nsource: APNIC\n",
                  "tags": [
                    "suspicious-udp"
                  ],
                  "country": "AU",
                  "last_analysis_date": 1675092552,
                  "last_analysis_stats": {
                    "harmless": 73,
                    "malicious": 2,
                    "suspicious": 0,
                    "undetected": 13,
                    "timeout": 0
                  },
                  "whois_date": 1672728840,
                  "last_analysis_results": {
                    "Bkav": {
                      "category": "undetected",
                      "result": "unrated",
                      "method": "blacklist",
                      "engine_name": "Bkav"
                    },
                    "CMC Threat Intelligence": {
                      "category": "harmless",
                      "result": "clean",
                      "method": "blacklist",
                      "engine_name": "CMC Threat Intelligence"
                    },
        
            ... result is truncated for brevity ...
            
            -------------
    
    
-c, --config
    This option is use to specify the config file to use. If this option is not specified, the script will use the default config file (virustotal.conf) in the same directory as the script.
    The script will create a new config file if it does not exist or it contains invalid data (you will be prompted to perform this action).
    
    eg:
        ./virustotal check --ip-address 1.2.3.4 --config /path/to/config/file
        
-o, --output
    This option is use to specify the output file to use. If this option is not specified, the script will use the default output file (virustotal_check_output.txt) in the same directory as the script.
    
    eg:
        ./virustotal check --ip-address 1.2.3.4 --output /path/to/output/file
        
-k, --cache
    This option is use to use previous scan output as cache. If this option is not specified, the script will perform a new scan.
    
    eg:
        ./virustotal check --ip-address 1.2.3.4 --cache

````
