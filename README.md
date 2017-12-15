# CSM Report Events


Disclaimer: This is sample code and is not supported by CloudPassage.

# Configure
To configure script add API Key information to cloudpassage.yml File
>key_id: your_api_key_id

>secret_key: your_api_secret_key  
  
To filter on a group add the Halo server group to target_halo_server_group = ""
in halo_csm_report_all_events.py  

# Requirements

This script requires Python 2.7.10 or greater
This script requires the CloudPassage Python SDK
> pip install cloudpassage

This script requires the Requests Python module.
>pip install requests

Install from pip with pip install cloudpassage. If you want to make modifications to the SDK you can install it in editable mode by downloading the source from this github repo, navigating to the top directory within the archive and running pip install -e . (note the . at the end). Or you can visit https://github.com/cloudpassage/cloudpassage-halo-python-sdk to clone it directly from our github.

# Running
Run *python halo_csm_report_all_events.py* to generate a CSV of all CSM alerts detected for all servers that have an agent state of 'active'.
