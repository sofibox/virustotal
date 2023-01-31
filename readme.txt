Script usage:
virustotal <+ action> <* options>, where + is required and * is optional


List of available actions:

check or scan

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

Other optional options:

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