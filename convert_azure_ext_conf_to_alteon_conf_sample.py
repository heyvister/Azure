#!/usr/bin/env python

###########################
# Originally written by:
# nissimn@radware.com
#Nissim Nisimov
###########################
# Version 1.0 - 19/Sep/2016
###########################
import fileinput

#make sure each parameters is in new line - only parameters and vaiables attributes are supported
#if need to support other attributes there is a need to change parsing script custom_data_convert_to_json.py

server_dict = {}
server_dict["SLB_PORT"] =     "parameters('SLBPortNumber')"
server_dict["REAL_COUNT"] =   "parameters('RealsCount')"
server_dict["REAL_1"] =       "parameters('Real1')"
server_dict["CLIENTID"] =     "parameters('ClientID')"
server_dict["CLIENTSECRET"] = "parameters('ClientSecret')"
server_dict["TENANTID"] =     "parameters('TenantID')"
server_dict["DNSSERVERIP"] =  "parameters('DNSServerIP')"
server_dict["RSRCGRP"] =      "variables('resourceGroupName')"
server_dict["SUBSCRIP"] =     "variables('subscripID')"
server_dict["NICNAME"] =      "variables('NICName')"
server_dict["PIPNAME"] =      "variables('PIPName')"
server_dict["PNICNAME"] =     "variables('PNICName')"
server_dict["SIPNAME"] =      "variables('SIPName')"
server_dict["SLB_METRIC"] =   "parameters('SLBMetric')"
server_dict["SS_NAME"] =      "scaleset1"
server_dict["REAL_SS_NAME"] = "parameters('realsScalesetName')"
server_dict["REALS_SS_RG"] =  "parameters('realsResourceGroupName')"
server_dict["VM_COUNT"] =     "parameters('vmCount')"
server_dict["FUNC_URL"] =     "variables('alteonAzureFuncUrl')"
server_dict["VM_COUNT"] =     "parameters('vmCount')"
server_dict["VM_ID"] =        VM_ID
server_dict["PRIVATE_IP_ADDRESS_PREFIX"] =  "variables('PrivateIPAddressPrefix')"
server_dict["PRIVATE_IP_ADDRESS_POSIX_START"] =  variables('PrivateIPAddressPosixStart')

#file which will hold the generated configuration
output_file=open("/mnt/cf/Alteon/config/azure_converted_config.txt", "a+")
real_count=0

def init_vars():
     global real_count
     if "REAL_COUNT" in server_dict:
        if int(server_dict["REAL_COUNT"]) > 0:
            real_count=server_dict["REAL_COUNT"]
        else:
            real_count=0

#convert  DNS server to Alteon if needed"
def convert_DNS_menu_to_config():
    if "DNSSERVERIP" in server_dict:
        if len(server_dict["DNSSERVERIP"]) > 1:
              if server_dict["DNSSERVERIP"] != "none":
                 output_file.write("/c/l3/dns\n\tprima " + server_dict["DNSSERVERIP"]+"\n")


#convert ActiveDirecory parameters and add DNS server to Alteon if needed"
def convert_AZURE_menu_to_config():
    azure_menu_on = 0;
    if "SUBSCRIP" in server_dict:
        if len(server_dict["SUBSCRIP"]) > 1:
              if server_dict["SUBSCRIP"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 # the format is /subscriptions/6c5564e0-54db-4d63-aa7b-1a7d78dd6f98 we need to skip the prefix and get only the ID
                 string_location = server_dict["SUBSCRIP"].find("/subscriptions/")
                 string_size  = string_location + 15
                 output_file.write("\tsubscrip " + server_dict["SUBSCRIP"][string_size:len(server_dict["SUBSCRIP"])]+"\n")
    if "CLIENTID" in server_dict:
        if len(server_dict["CLIENTID"]) > 1:
              if server_dict["CLIENTID"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 output_file.write("\tclient " + server_dict["CLIENTID"]+"\n")
    if "CLIENTSECRET" in server_dict:
        if len(server_dict["CLIENTSECRET"]) > 1:
              if server_dict["CLIENTSECRET"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 output_file.write("\tsecret\n\t" + server_dict["CLIENTSECRET"] + "\n")
    if "TENANTID" in server_dict:
        if len(server_dict["TENANTID"]) > 1:
              if server_dict["TENANTID"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 output_file.write("\ttenant " + server_dict["TENANTID"]+"\n")
    if "RSRCGRP" in server_dict:
        if len(server_dict["RSRCGRP"]) > 1:
              if server_dict["RSRCGRP"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 output_file.write("\trsrcgp " + server_dict["RSRCGRP"]+"\n")
    if "NICNAME" in server_dict:
        if len(server_dict["NICNAME"]) > 1:
              if server_dict["NICNAME"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 if (server_dict["VM_ID"]) == 1:
                    output_file.write("\tnicname " + server_dict["NICNAME"]+"\n")
                 elif (server_dict["VM_ID"]) == 2:
                    output_file.write("\tpnicname " + server_dict["NICNAME"]+"\n")
    if "PIPNAME" in server_dict:
        if len(server_dict["PIPNAME"]) > 1:
              if server_dict["PIPNAME"] != "none":
                 if (azure_menu_on == 0):
                     azure_menu_on = 1
                     output_file.write("/c/sys/azure\n" )
                 output_file.write("\tpipname " + server_dict["PIPNAME"]+"\n")
    if "PNICNAME" in server_dict:
        if (server_dict["VM_COUNT"]) == "2":  
            if len(server_dict["PNICNAME"]) > 1:
                  if server_dict["PNICNAME"] != "none":
                     if (azure_menu_on == 0):
                         azure_menu_on = 1
                         output_file.write("/c/sys/azure\n" )
                     if (server_dict["VM_ID"]) == 1:
                        output_file.write("\tpnicname " + server_dict["PNICNAME"]+"\n")
                     elif (server_dict["VM_ID"]) == 2:
                        output_file.write("\tnicname " + server_dict["PNICNAME"]+"\n")
    if "SIPNAME" in server_dict:
        if (server_dict["VM_COUNT"]) == "2":
            if len(server_dict["SIPNAME"]) > 1:
                  if server_dict["SIPNAME"] != "none":
                     if (azure_menu_on == 0):
                         azure_menu_on = 1
                         output_file.write("/c/sys/azure\n" )
                     output_file.write("\tsipname " + server_dict["SIPNAME"]+"\n")


#convert slb port to "/c/slb/virt 1/service X http"
def convert_service_to_config():
    if "SLB_PORT" in server_dict:
       if len(server_dict["SLB_PORT"]) > 0:
          output_file.write("/c/slb/virt 1\n\tena\n")
          output_file.write("\tgroup 1\n")
          output_file.write("\trport 80\n")
          output_file.write("/c/slb/virt 1/service "+ server_dict["SLB_PORT"] + " http\n")



#convert reals to "/c/slb/real x/rip y.y.y.y/ena"
def convert_reals_to_config():
    if len(server_dict["REAL_1"]) > 1:
        if server_dict["REAL_1"] != "none":
            output_file.write("/c/slb/real " + "1" + "\n\tdis\n "+"\trip "+ server_dict["REAL_1"]+"\n")



#add reals and metric to group "/c/slb/group 1/add x /c/slb/group 1/metric x"
def convert_group_to_config():
    if int(real_count) > 0:
        output_file.write("/c/slb/group 1\n")
        if "SLB_METRIC" in server_dict:
           if len(server_dict["SLB_METRIC"]) > 0:
              if server_dict["SLB_METRIC"] != "none":
                 output_file.write("\tmetric "+ server_dict["SLB_METRIC"]+ "\n")

        if len(server_dict["REAL_1"]) > 1:
            if server_dict["REAL_1"] != "none":
                output_file.write("\tadd " + "1" + "\n")

#convert to HA configuration"
def convert_ha_to_config():
    #check if we are in HA mode
    if (server_dict["VM_COUNT"]) == "2":
        output_file.write("/c/l3/hamode switch\n")
        output_file.write("/c/l3/ha/switch\n\tdef 1\n")

#convert reals scaleset configuration"
def convert_reals_scaleset_to_config():
    fqdn_menu_on = 0
    if "REAL_SS_NAME" in server_dict:
        if len(server_dict["REAL_SS_NAME"]) > 1:
              if server_dict["REAL_SS_NAME"] != "none":
                 if (fqdn_menu_on == 0):
                     fqdn_menu_on = 1
                     output_file.write("/c/slb/adv/fqdnreal " + server_dict["SS_NAME"] + "\n" )
                     output_file.write("\tgroup 1\n")
		     output_file.write("\tmode cscale\n")
                     output_file.write("\tena\n")
			
                 output_file.write("\tfqdn " + server_dict["REAL_SS_NAME"]+"\n")

    if "REALS_SS_RG" in server_dict:
        if len(server_dict["REALS_SS_RG"]) > 1:
              if server_dict["REALS_SS_RG"] != "none":
                 if (fqdn_menu_on == 0):
                     fqdn_menu_on = 1
                     output_file.write("/c/slb/adv/fqdnreal " + server_dict["SS_NAME"] + "\n" )
                     output_file.write("\tgroup 1\n")
                     output_file.write("\tmode cscale\n")
                     output_file.write("\tena\n")

                 output_file.write("\trsrcgrp " + server_dict["REALS_SS_RG"]+"\n")


#Add HC probe 8080"
def add_hc_probe_to_config():
    output_file.write("/c/sys/health\n\ton\n\tadd 8080\n")

#convert to Azure function URL"
def convert_azure_function_url_to_config():
     output_file.write("/c/sys/azure/funcurl \n\t"+ server_dict["FUNC_URL"]+ "\n")

#convert to interface configuration"
def convert_interface_peer_to_config():
    #check if we are in HA mode
    if (server_dict["VM_COUNT"]) == "2":
        private_ip_master_peer = server_dict["PRIVATE_IP_ADDRESS_POSIX_START"]+1
        #we need to edit the interface ip and enable it so Alteon accept the config
        if (server_dict["VM_ID"]) == 1:
            output_file.write("/c/l3/if 1\n\tena\n\taddr " + server_dict["PRIVATE_IP_ADDRESS_PREFIX"] + str(server_dict["PRIVATE_IP_ADDRESS_POSIX_START"])  +"\n")
            output_file.write("\tpeer " + server_dict["PRIVATE_IP_ADDRESS_PREFIX"] + str(private_ip_master_peer) +"\n")
        elif (server_dict["VM_ID"]) == 2:
            output_file.write("/c/l3/if 1\n\tena\n\taddr " + server_dict["PRIVATE_IP_ADDRESS_PREFIX"] + str(private_ip_master_peer)  +"\n")
            output_file.write("\tpeer " + server_dict["PRIVATE_IP_ADDRESS_PREFIX"] + str(server_dict["PRIVATE_IP_ADDRESS_POSIX_START"]) + "\n")


init_vars()
convert_interface_peer_to_config()
convert_DNS_menu_to_config()
convert_reals_to_config()
convert_group_to_config()
#convert_service_to_config()
convert_ha_to_config()
convert_reals_scaleset_to_config()
add_hc_probe_to_config()
convert_azure_function_url_to_config()
convert_AZURE_menu_to_config()
