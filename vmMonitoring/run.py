import os
import sys
import urllib2
import urllib
import json
import collections
import itertools
import xml.etree.ElementTree as et
from datetime import datetime
import hmac
import ssl



##### TO DO ####
# LOOK INTO AZURE KEY VAULT 
# USE IN PYTHON?

PARAMETERS_FILE='parameters.json'

#### BEGIN USER INPUT ######
#Application ID
#client_id = 'c24ae642-5f0d-4a40-ad2c-3c614d9f0f02'
#Key
#client_secret = 'IgItvntUD3Rb8gwt8btRwXYo1cQnNOKhdaibA+0Yitw='
#Directory ID
#tenant_id = '66b66353-3b76-4e41-9dc3-fee328bd400e'
#Azure subscription ID
#subscription_id = '93486f84-8de9-44f1-b4a8-f66aed312b64'

#Comma separated list of resource groups to be monitored.
#For example ResourceGroupList = ['rg1', 'rg2']
#ResourceGroupList = ['jkwon-function']

#Comma separated list of Firewall IPs or FQDNs of the management interface
#For example FirewallLsit = ['1.1.1.1', '2.2.2.2']
#FirewallList= ['10.3.0.4']
#FirewallList= ['52.165.164.185']


#Comma separated list of API keys. Make sure the fw list and api key list match
#For example apikeyList = ['api key for fw with ip 1.1.1.1', 'api key for fw with ip 2.2.2.2']
#apikeyList = ['LUFRPT1yelhSUEtaalovSFRUWm12cTNyd2YxM3BtN0E9em5HYjZES1JLU0xuTEtlbkNJdkEwNHVvMWVCT1hITW1GUDNZTk9aMWsrVT0=']
##### END USER INPUT ########

list_types = [ 'resourceGroups', 'targetIps', 'targetApiKeys' ]
required_params = [ 
    "clientId",
    "clientSecret",
    "tenantId",
    "subscriptionId",
    "targetIps",
    "targetApiKeys",
    "targetVsys",
    "verboseLoggingEnable"
    ]

param_dict = {}

apiVersion = '2016-04-30-preview'
access_token = ""
token_type = ""


NewIPTagList = collections.defaultdict(list)
CurrentIPTagList = collections.defaultdict(list)





def Send_Azure_REST(url):
    global access_token, token_type
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', '%s %s' %(token_type, access_token))
    print url
    try:
        f = urllib2.urlopen(req).read()
    except urllib2.HTTPError as err:
        if err.code == 404:
            print ("Resource Group not found...maybe? Got a 404 error. going to exit for now")
            sys.exit(0)
    else:
        #w = json.loads(f)
        w = json_loads_byteified(f)
        return w

def GetResourceGroups(subscription_id):
    global param_dict
    param_dict['resourceGroups'] = []
    #url = "https://management.azure.com/subscriptions/"+param_dict['subscriptionId']+"/resourcegroups?$top=50&api-version=2017-05-10"
    url = "https://management.azure.com/subscriptions/"+param_dict['subscriptionId']+"/resourcegroups?api-version=2017-05-10"
    output = Send_Azure_REST(url)
    #print output
    for dict in output['value']:
        for key,val in dict.iteritems():
            if key == 'name':
                param_dict['resourceGroups'].append(val)

def Build_Tags(RG):
    global NewIPTagList
    url = "https://management.azure.com/subscriptions/"+param_dict['subscriptionId']+"/resourceGroups/"+RG+"/providers/Microsoft.Network/networkInterfaces?api-version=2017-08-01"       
    output = Send_Azure_REST(url)
    print "Build Tags output: %s" % output
    #url_debug = "https://jkwonfnstorage1.file.core.windows.net/debuglogs/debug.log.%s" % datetime.now().strftime("%Y%m%d")
    #output_debug = Send_Azure_REST(url_debug)
    #print "debug logging output: %s" % output_debug
    for key in output['value']:
        #Get ip address of the interface
        ipaddress = key['properties']['ipConfigurations'][0]['properties']['privateIPAddress']
        #VM name that the interface is attached to
        try:
            vmname = key['properties']['virtualMachine']['id'].split('/')[-1]
        except:
            print "NIC not attached to any VM; skipping."
            continue
        #Subnet tht the interface reside sin 
        subnet = key['properties']['ipConfigurations'][0]['properties']['subnet']['id'].split('/')[-1]

        #Populate the list of tags
        NewIPTagList[ipaddress].append('azure-tag.vmname.'+str(vmname))
        NewIPTagList[ipaddress].append('azure-tag.subnet.'+str(subnet))

        rg_url = "https://management.azure.com/subscriptions/"+param_dict['subscriptionId']+"/resourceGroups/"+RG+"/providers/Microsoft.Compute/virtualmachines/"+vmname+"?$expand=instanceView&api-version="+apiVersion
        try:
            rg_output = Send_Azure_REST(rg_url)
        except:
            print "VM not found; may be in different RG than NIC"
            continue
         #Get the OS type
        NewIPTagList[ipaddress].append('azure-tag.GuestOS.'+str(rg_output['properties']['storageProfile']['osDisk']['osType']))
        #Get Running state of VM
        for status in rg_output['properties']['instanceView']['statuses']:
            if 'PowerState' in status['code']:
                if status['code'].split('/')[-1] == 'deallocated':
                    NewIPTagList[ipaddress].append('azure-tag.vmPowerState.Stopped')
                else: 
                    NewIPTagList[ipaddress].append('azure-tag.vmPowerState.'+str(status['code'].split('/')[-1]))
       

        #User defined tags
        if rg_output.get('tags') is not None:
                for k, v in rg_output.get('tags').iteritems():
                    NewIPTagList[ipaddress].append('azure-tag.'+str(k)+"."+str(v))


def Get_Azure_Access_Token():
    global access_token, token_type
    #data = "grant_type=client_credentials&resource=https://management.core.windows.net/&client_id=%s&client_secret=%s" % (param_dict['clientId'], param_dict['clientSecret'])
    data_to_encode = { 'grant_type' : 'client_credentials', 'resource' : 'https://management.core.windows.net/', 'client_id' : param_dict['clientId'], 'client_secret' : param_dict['clientSecret'] }
    data = urllib.urlencode(data_to_encode)
    url = "https://login.microsoftonline.com/%s/oauth2/token?api-version=1.0" % (param_dict['tenantId'])
    req = urllib2.Request(url, data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    f = urllib2.urlopen(req)
    for x in f:
        y = json.loads(x)
        if y['token_type'] == 'Bearer':
            access_token = y['access_token']
            token_type = y['token_type']
    f.close()

def Generate_XML(Register, Unregister):    

#CurrentIPTagList is the list of IP to Tag mapping in the Firewall.
#NewIPTagList is the list of IP to Tag mapping in the Azure environment.
#This function will find the delats between the new ip to tag mappings and register new IPs and tags 
#And unregister IPs from tags that have disappeared.
    print "current: %s" % CurrentIPTagList.keys()
    print "new: %s" % NewIPTagList.keys()
    for k1 in CurrentIPTagList.keys():
        if k1 in NewIPTagList.keys():
            ip = k1
            tags = list(set(CurrentIPTagList[k1]) - set(NewIPTagList[k1]))
        elif k1 not in NewIPTagList.keys():
            ip = k1
            tags = CurrentIPTagList[k1]
        if tags:            
            Unregister += '<entry ip="' + ip + '">'
            Unregister += "<tag>"
            for i in tags:
                Unregister += '<member>' + i + '</member>'
            Unregister += "</tag>"
            Unregister += "</entry>"

    print "unregister: " + Unregister
    for k1 in NewIPTagList.keys():
        if k1 in CurrentIPTagList.keys():
            ip = k1
            tags = list(set(NewIPTagList[k1]) - set(CurrentIPTagList[k1]))
        elif k1 not in CurrentIPTagList.keys():
            ip = k1
            tags = NewIPTagList[k1]
        if tags:
            Register += '<entry ip="' + ip + '">'
            Register += "<tag>"
            for i in tags:
                Register += '<member>' + i + '</member>'
            Register += "</tag>"
            Register += "</entry>"
    print "register: " + Register
    return Unregister, Register
    
#Get the list of IP to tag mappings that are in the firewall
def Firewall_Get_Tags(firewall_mgmt_ip, api_key):
    global CurrentIPTagList
    url = "https://%s/api/?type=op&cmd=<show><object><registered-ip><all/></registered-ip></object></show>&key=%s" %(firewall_mgmt_ip, api_key)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        response = urllib2.urlopen(url, context=ctx).read()
        #print response
    except urllib2.HTTPError, e:
        print "HTTPError = " + str(e)
    else:
        print "Get Tags: %s" % response
        root = et.fromstring(response)
        if root.attrib['status'] == 'success':
            for entry in root.findall('./result/entry'):
                for tag in entry.findall('./tag/member'):
                    CurrentIPTagList[entry.attrib['ip']].append(tag.text)



#Update the firewall with the latest IP to tag map
def Firewall_Update_Tags(firewall_mgmt_ip, api_key, FWXMLUpdate):
    url = "https://%s/api/?" % firewall_mgmt_ip
    data = "type=user-id&action=set&key=%s&vsys=%s&cmd=%s" % (api_key, param_dict['targetVsys'], urllib.quote(FWXMLUpdate))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib2.Request(url, data)
    print data
    try:
        response = urllib2.urlopen(req, context=ctx).read()
        #print response
    except urllib2.HTTPError, e:
        print "HTTPError = " + str(e)
    else:
        print "Update Tags %s" % response

#Check HA status.  Only push tags to Active or Active-Primary devices
def is_ha_primary(firewall_mgmt_ip, api_key):
    url = "https://%s/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=%s" %(firewall_mgmt_ip, api_key)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        response = urllib2.urlopen(url, context=ctx).read()
        #print response
    except urllib2.HTTPError, e:
        print "HTTPError = " + str(e)
        return False

    root = et.fromstring(response)
    if root.attrib['status'] == 'success':
        for entry in root.findall('./result/enabled'):
            if entry.text == 'yes':
                print "HA enabled"
                #for entry in root.findall('./result/group/mode'):
                #    print entry.text
                for entry in root.findall('./result/group/local-info/state'):
                    print entry.text
                    if entry.text.lower() == 'active' or entry.text.lower() == 'active-primary':
                        print "Firewall is %s" % entry.text
                        return True
            else:
                print "HA disabled"
                return True
    return False

#Helper functions to convert unicode strings
def json_load_byteified(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )

def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data

#Retrieve parameters from parameters file
def read_parameters(filename=PARAMETERS_FILE):
    global param_dict

    data = json_load_byteified(open(filename))
    for key,val in data['parameters'].iteritems():
        if key in list_types:
            param_dict[key] = val['value'].split(',')
        else:
            param_dict[key] = val['value']
    for item in required_params:
        if item not in param_dict:
            print "Missing required parameter: %s" % item
            sys.exit(1)

#Entry point
def main():
    read_parameters(PARAMETERS_FILE)
    FWXMLUpdate = []
    XMLHeader = "<uid-message><version>1.0</version><type>update</type><payload>"
    XMLFooter = "</payload></uid-message>"
    Unregister = "<unregister>"
    Register = "<register>"


#check to see if firewall is reachable. If not, gracefully exit
    for Firewall in param_dict['targetIps']:
        url = "https://%s" %(Firewall)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            f = urllib2.urlopen(url, timeout=5, context=ctx)
        except urllib2.URLError as err:
            print err
            print ("FW not found...Exiting for now")
            sys.exit(0)
            

            

#Authenticate and get access token so we can make API calls into Azure
    Get_Azure_Access_Token()
    print "Access Token retrieved"

#Get resource group list
    GetResourceGroups(param_dict['subscriptionId'])

#Build the list of IP to tag
    print "ResourceGroupList %s" % param_dict['resourceGroups']
    for ResourceGroup in param_dict['resourceGroups']:
        # XXX delete this check
        if ResourceGroup.startswith('jk'):
            Build_Tags(ResourceGroup)

#Get ip-to-tag mapping from the firewall
    for Firewall,api_key in itertools.izip(param_dict['targetIps'], param_dict['targetApiKeys']):
        if is_ha_primary(Firewall, api_key):
            Firewall_Get_Tags(Firewall, api_key)

    Unregister, Register = Generate_XML(Register, Unregister)

    Register += "</register>"
    Unregister += "</unregister>"
    FWXMLUpdate = XMLHeader + Unregister + Register + XMLFooter

    print FWXMLUpdate
    for Firewall,api_key in itertools.izip(param_dict['targetIps'], param_dict['targetApiKeys']):
        if is_ha_primary(Firewall, api_key):
            Firewall_Update_Tags(Firewall, api_key, FWXMLUpdate)


if __name__ == "__main__":
     main()
