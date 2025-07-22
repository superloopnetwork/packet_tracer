 from panos.firewall import Firewall
 from pprint import pprint
 import xml.etree.ElementTree as ET 
 import argparse
 import os
 import getpass
 import re
 
 def iptobin(ip): #convert an IP address to binary representation
     ip_nums = ip.split(".")
     ip_bits = ""
     for num in ip_nums:
         bits = bin(int(num))[2:]
         while len(bits) < 8:
             bits = "0" + bits
         ip_bits += bits
     return ip_bits
 
 def ipmatch(ip, ipstr): #match an IP with possible IP with slash notation (ipstr)
     is_ip = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9][0-9]?$", ipstr)
     if not is_ip:
         return False
     ip_bits = iptobin(ip)
     ipstr_bits = iptobin(ipstr.split("/")[0])
     for i in range(int(ipstr.split("/")[1])):
         if ip_bits[i] != ipstr_bits[i]:
             return False
     return True
 
 def is_RFC1918(ip): #determine if an IP address is RFC1918
     if ip[:3] == "10.":
         return True
     if ip[:4] == "172.":
         if int(ip[4:6]) >= 16 and int(ip[4:6]) <= 31 and ip[6] == ".":
             return True
     if ip[:7] == "192.168":
         return True
     return False
 
 #Set up argument parser
 parser = argparse.ArgumentParser(description="Test what securityrule a connection hits on a firewall",formatter_class=argparse.ArgumentDefaultsHelpFormatter)
 parser.add_argument("firewall", help="Firewall to check, IP or Name")
 parser.add_argument("--source", help="Source IP", required=True)
 parser.add_argument("--destination", help="Destination IP", required=True)
 parser.add_argument("--port", help="Destination port", required=True)
 parser.add_argument("--application", help="The application")
 parser.add_argument("--from", help="from zone")
 parser.add_argument("--to", help="to zone")
 
 #parse the input
 args = parser.parse_args()
 config = vars(args)
 print(config)
 print()
 
 #check if given ips are valid
 is_ip = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", config["source"])
 if not is_ip:
     print("Source IP is invalid")
     exit()
 is_ip = re.search(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", config["destination"])
 if not is_ip:
     print("Destination IP is invalid")
     exit()
 
 #check if the given firewall is valid
 firewalls = {"x.x.x.x":"x.x.x.x", "fw1":"x.x.x.x", "y.y.y.y":"y.y.y.y", "fw2":"y.y.y.y"} #dictionary of possible firewall inputs -> firewall IP
 if not config["firewall"] in firewalls.keys():
     print("Firewall not recognized, possible values:", list(firewalls.keys()))
     exit()
 
 #get username and password
 if 'NETWORK_USERNAME' in os.environ:
         user = os.environ.get('NETWORK_USERNAME')
 else:
         user = os.environ.get('USER') 
 
 if 'NETWORK_PASSWORD' in os.environ:
         password = os.environ.get('NETWORK_PASSWORD')
 else:
     password = getpass.getpass()
 
 #set the correct firewall
 if firewalls[config["firewall"]] == "x.x.x.x":
     fw = Firewall("x.x.x.x", user, password, vsys="vsys1")
 else:
     fw = Firewall("y.y.y.y", user, password, vsys="vsys1")
 
 #get list of interfaces from the firewall, check if any match the source or destination
 interface_string = '<show><interface>logical</interface></show>'
 try:
     interface_response = fw.op(interface_string,cmd_xml=False, xml=True)
     interface_root = ET.fromstring(interface_response)
 except Exception as error:
     print("An exception occured:", error)
     exit()
 
 for entry in interface_root.findall("./result/ifnet/entry"):
     entry_ip = entry.find("ip").text
 
     if config["from"] == None and ipmatch(config["source"], entry_ip):
         from_zone = entry.find("zone").text
         config["from"] = from_zone
         print("Source matches interface zone:", from_zone)
 
     if config["to"] == None and ipmatch(config["destination"], entry_ip):
         to_zone = entry.find("zone").text
         config["to"] = to_zone
         print("Destination matches interface zone:", to_zone)
 
 
 if config["from"] == None:
     #default to "kobo-production" virtual router for RFC1918 addresses, otherwise "public" virtual router
     if is_RFC1918(config["source"]):
         virtual_router = "kobo-production"
     else:
         virtual_router = "public"
 
     try:
         #get the source interface
         from_string = '<test><routing><fib-lookup><virtual-router>{}</virtual-router><ip>{}</ip></fib-lookup></routing></test>'.format(virtual_router,config["source"])
         from_response = fw.op(from_string, cmd_xml=False, xml=True)
         from_root = ET.fromstring(from_response)
         from_interface = from_root.find("./result/interface").text
 
         #get the source zone
         from_zone_string = '<show><interface>{}</interface></show>'.format(from_interface)
         from_zone_response = fw.op(from_zone_string, cmd_xml=False, xml=True)
         from_zone_root = ET.fromstring(from_zone_response)
         from_zone = from_zone_root.find("./result/ifnet/zone").text
         print("Found source zone:",from_zone)
         config["from"] = from_zone
     except Exception as error:
         print("An exception occured while finding the source zone:", error)
         exit()
 
 if config["to"] == None:
     #default to "kobo-production" virtual router for RFC1918 addresses, otherwise "public" virtual router
     if is_RFC1918(config["source"]):
         virtual_router = "kobo-production"
     else:
         virtual_router = "public"
 
     try:
         #get the destination interface
         to_string = '<test><routing><fib-lookup><virtual-router>{}</virtual-router><ip>{}</ip></fib-lookup></routing></test>'.format(virtual_router,config["destination"])
         to_response = fw.op(to_string, cmd_xml=False, xml=True)
         to_root = ET.fromstring(to_response)
         to_interface = to_root.find("./result/interface").text
 
         #get the destination zone
         to_zone_string = '<show><interface>{}</interface></show>'.format(to_interface)
         to_zone_response = fw.op(to_zone_string, cmd_xml=False, xml=True)
         to_zone_root = ET.fromstring(to_zone_response)
         to_zone = to_zone_root.find("./result/ifnet/zone").text
         print("Found destination zone:",to_zone)
         config["to"] = to_zone
     except Exception as error:
         print("An exception occured while finding the destination zone:", error)
         exit()
 
 
 #get application from the port number
 if config["application"] == None:
     application_dict = {"21": "ftp", "22": "ssh", "25": "smtp-base", "53": "dns-base", "80": "web-browsing", "88": "kerberos", "123": "ntp-base", "443": "ssl", "3306": "mysql", "8080": "web-browsing", "8200": "ssl"}
     if config["port"] in application_dict:
         config["application"] = application_dict[config["port"]]
         print("Most likely application:", config["application"])
     else:
         config["application"] = "unknown-tcp"
         print("Application defaulting to unknown-tcp")
 
 #build the test string to be sent to the firewall
 test_string = "test security-policy-match"
 test_string += ' source "' + str(config["source"]) + '"'
 test_string += ' destination "' + str(config["destination"]) + '"'
 test_string += ' protocol "6" ' 
 test_string += ' destination-port "' + str(config["port"]) + '"'
 if config["application"] != None:
     test_string += ' application "' + str(config["application"]) + '"'
 test_string += ' from "' + str(config["from"]) + '"'
 test_string += ' to "' + str(config["to"]) + '"'
 
 #print(test_string)
 try:
     element_response = fw.op(test_string, xml=True)
     root = ET.fromstring(element_response)
     #print(element_response)
 except Exception as error:
     print("An exception occured:", error)
     exit()
 
 #print(root.tag)
 if root.attrib["status"] == "success":
     print()
     print("Successfully received firewall response")
 else:
     print("There was an error finding the security rule")
     print("Firewall response:")
     print(element_response)
     exit()
 
 
 #find matching entry security rule
 result = root.findall("./result/rules/entry")
 
 if len(result) == 0:
     print("No matching security rule was found.")
     exit()
 
 #print out the matching security rule(s) (though there should only be one)
 for i in result:
     action = "unknown"
 
     #print(i.tag)
     rule_name = i.attrib["name"]
     print("Name:", rule_name)
 
     for j in i:
         print("    " + str(j.tag), end=": ")
         text = j.text
         if text.strip() == '':
             members = []
             for k in j:
                 members.append(k.text)
             print(members)
         else:
             print(j.text)
             if j.tag == "action":
                 action = j.text
 
     print()
     if action == "allow":
         print("This connection is currently allowed by the firewall.")
     else:
         print("The current firewall action is: " + action)
     #send another command to the firewall to get the hit count
     hit_count_command = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><list><member>{}</member></list></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>".format(rule_name)
     hit_count_element_response = fw.op(hit_count_command, cmd_xml=False, xml=True)
     hit_command_root = ET.fromstring(hit_count_element_response)
     if root.attrib["status"] == "success":
         hit_count = hit_command_root.find("./result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry/hit-count")
         print("Rule hit count:", hit_count.text)
     else:
         print("Unable to get rule hit count.")
 
 
     print()
