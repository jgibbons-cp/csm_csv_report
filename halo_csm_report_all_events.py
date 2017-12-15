# WARNING: This script takes a long time to execute if you have a high count
#          of active servers.
# Author: Mark A. Aklian
# Version 1.0.0
# Date 10.02.2017
##############################################################################

# Import Python Modules
import cloudpassage
import os
import sys
import time


def create_api_session(session):

    config_file_loc = "cloudpassage.yml"
    config_info = cloudpassage.ApiKeyManager(config_file=config_file_loc)

    # authenticate to get a session object
    session = cloudpassage.HaloSession(config_info.key_id,
                                       config_info.secret_key)

    return session

##
#
#   Get a server group ID by server group name
#
#   Parameters -
#
#       server_group_obj (object) - server group object
#       server_group_name (str) - name of server group
#
#    Return -
#
#       server_group_id (str) - server group ID
#
###


def get_server_group_id_by_name(server_group_obj, target_server_group_name):
    server_groups = server_group_obj.list_all()
    server_group_id = None

    for server_group in server_groups:
        server_group_name = server_group["name"].encode('utf-8')

        if server_group_name == target_server_group_name:
            server_group_id = server_group["id"]
            break

    return server_group_id


def get_scan_data(session):
    mode = "w"
    report_directory = "reports/"
    report_name = "CSM_report_all_events_"
    report_extension = ".csv"

    if not os.path.exists(report_directory):
        os.makedirs(report_directory)

    out_file = "%s%s" % (report_directory, report_name) \
               + time.strftime("%Y%m%d-%H%M%S") + report_extension
    ofile = open(out_file, mode)

    halo_server_list = get_halo_servers_id(session)

    ofile.write('AWS Account ID, Halo Server ID, AWS Instance ID,'
                'CSM Rule Name, '
                'Rule Description, Expected Target Value for Check, Actual '
                'Value\n')

    server_count = 1
    increment = 1
    scan_type = "sca"

    total_servers = len(halo_server_list)

    for server in halo_server_list:
        print "Processing {0} of {1} servers".format(server_count,
                                                     total_servers)
        server_count += increment

        # get the last csm scan
        cp_scan_ob = cloudpassage.Scan(session)
        data = cp_scan_ob.last_scan_results(server['halo_server_id'],
                                            scan_type)

        if 'scan' in data:
            current_findings = data['scan']['findings']

            for finding in current_findings:
                if finding['status'] == 'bad':
                    # and finding['critical'] is True:

                    finding_details = finding['details']

                    for details in finding_details:

                        if details['status'] == 'bad':
                            expected_value = details['expected']

                            # strip commas if var is a str
                            if not isinstance(expected_value, bool):
                                expected_value = str(expected_value)
                                expected_value = \
                                    expected_value.replace(",", " ")

                            # set to space if they key does not exist
                            if 'rule_description' not in finding:
                                rule_description = " "
                            else:
                                # if the key does exist then strip the returns
                                # and newlines and commas
                                rule_description = \
                                    finding['rule_description']
                                rule_description = \
                                    rule_description.replace(",", " ")
                                rule_description = \
                                    rule_description.replace("\r", "")
                                rule_description = \
                                    rule_description.replace("\n", "")

                            row = "'{0}',{1},{2},{3},{4},{5},{6}\n" \
                                  "".format(server['aws_account_id'],
                                            server['halo_server_id'],
                                            server['aws_instance_id'],
                                            finding['rule_name'],
                                            rule_description,
                                            expected_value,
                                            details['actual'])
                            row = str(row)
                            ofile.write(row)

    ofile.close()


# Query Halo API /v1/servers to get list of servers and extract Instance ID,
# AWS Account ID, and Halo Server ID
def get_halo_servers_id(session):

    NO_SERVERS = 0
    target_halo_server_group = ""
    cp_server_ob = cloudpassage.Server(session)
    cp_server_group_ob = cloudpassage.ServerGroup(session)

    if target_halo_server_group == "":
        halo_server_list = cp_server_ob.list_all(state="active")
    else:
        server_group_id = \
            get_server_group_id_by_name(cp_server_group_ob,
                                        target_halo_server_group)
        halo_server_list = cp_server_group_ob.list_members(server_group_id)

    if len(halo_server_list) == NO_SERVERS:
        print "No server to use... exiting...\n"
        sys.exit(1)

    halo_server_id_list = []
    for server in halo_server_list:
        if 'aws_ec2' in server:
            ec2_data = server['aws_ec2']
            halo_server_id_list.append({
                'halo_server_id': server['id'],
                'aws_instance_id': ec2_data['ec2_instance_id'],
                'aws_account_id': ec2_data['ec2_account_id']})
        elif server['server_label'] and "_" in server['server_label']\
                and server['server_label'] is not None:
            server_label = server['server_label']
            server_label_parts = server_label.split("_")
            server_label_account = server_label_parts[0]
            server_label_instance = server_label_parts[1]
            halo_server_id_list.append({
                'halo_server_id': server['id'],
                'aws_instance_id': server_label_instance,
                'aws_account_id': server_label_account})
        else:
            halo_server_id_list.append({
                'halo_server_id': server['id'],
                'aws_instance_id': "N/A",
                'aws_account_id': "N/A"})

    halo_instance_id_list = halo_server_id_list
    print "Halo Server ID and AWS Account ID Lookup Complete "\
          + time.strftime("%Y%m%d-%H%M%S")

    return halo_instance_id_list


if __name__ == "__main__":
    api_session = None
    api_session = create_api_session(api_session)
    get_scan_data(api_session)
