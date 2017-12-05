# in case this is run in python2.x
from __future__ import print_function, division
import re
from networktools import NetworkTools
from rulecompression import RuleCompression
# This is used for sorting the final list
from operator import itemgetter


class Normalization:
    def __init__(self):
        # Create an instance of NetworkTools
        self.nettools = NetworkTools()
        # Rule counter for debugging
        self.ruleCounter = 0
        # Change or ticket number to reference
        self.changeNumber = 'CHG10077905'
        # filename to read from
        self.filename = '/Users/douglas.colthar/Downloads/raw-acl.txt'
        # The outerlist that holds the inner lists of rules read from the file
        self.outerList = []
        # The list of completed rules added as the process completes
        self.ruleList = []
        # A list to store the service names in so they can be built and output to screen only once
        self.servicesToBuild = []
        # num pattern is used to see if items start with numbers later
        self.numPattern = re.compile("^[0-9]")
        # A list of services common in Cisco ASA ACLs
        self.serviceList = {
            'netbios-ssn':'139',
            'netbios-dgm':'138',
            'netbios-ns':'137',
            'ldap':'389',
            'ldaps':'636',
            'ssh':'22',
            'http':'80',
            'https':'443',
            'domain':'53',
            'sqlnet':'1521',
            'ftp-data':'20',
            'ftp':'21',
            'www':'80',
            'smtp':'25',
            'pop3':'110',
            'imap4':'143',
            'ntp':'123'
        }

    def printSpacer(self):
        '''
        Literally prints a line of text to space out sections
        :return:
        '''

        print('\n' + '*' * 100 + '\n')

    def readFile(self):
        '''
        Reads the file with raw data
        :return: returns a dictionary of the rules
        '''
        with open(self.filename) as f:
            # return the dictionary from reading f
            return f.readlines()

    def normalizeFile(self):
        '''
        This method will take in the file input and strip out things like lines with object-group
        :return:
        '''
        rawOutput = self.readFile()
        # split the object and add each sublist to the outerList
        for i in rawOutput:
            if 'object-group' in i:
                continue
            else:
                # split into a list to put inside outerList
                temp = i.rstrip().split()
                # delete the hitcount and hexnumber at the end
                del temp[-2:]
                # delete the access-list, security zone from ASA, line, line number and extended
                del temp[:5]
                # Append the list to outerList only if the list isn't blank
                if temp:
                    self.outerList.append(temp)

    def checkObjects(self, object):
        '''
        See if an object is in the database and if so return the port number of the object
        :param object: the object name to check
        :return: port-number
        '''
        return(self.serviceList[object])

    def generateRules(self):
        '''
        Take the outerList output and create base rules
        You can then send the self.ruleList to the RuleCompression object to reduce the number of rule names
        :return:
        '''

        # you will have common info that gets set like srcMask, dstMask, srcIP, dstIP, srcPort, dstPort, protocol
        for i in self.outerList:
            # service statement will include the application and service
            serviceStatement = ''
            srcMask = ''
            dstMask = ''
            srcIP = ''
            dstIP = ''
            srcFull = ''
            dstFull = ''

            # Wave
            if i[1] == 'ip':
                serviceStatement = 'service any'
            elif i[1] == 'icmp':
                serviceStatement = 'application ping service any'
            elif i[1] == 'tcp' or i[1] == 'udp':
                protocol = i[1]
                # destination port placeholder
                dstPort = ''

                # If the source port is gt and the destination port is equal to
                if i[4] == 'gt' and (i[8] == 'eq' or i[8] == 'gt'):
                    # Whether its the start port or the ultimate port we can still do this
                    dstPort = i[9]
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)

                    # We have to name it slightly different and build the object different depending
                    # on if its an eq or a gt
                    if i[8] == 'eq':
                        # object for service name
                        serviceName = 'AFG-{protocol}-SRC{srcPort}-DST{dstPort}'.format(dstPort=dstPort, protocol=protocol, srcPort=i[5] + '-65535').upper()
                        # we have to check to see if the port is in the object database if its a name
                        if not dstPort.isdigit():
                            dstPort = self.checkObjects(object=dstPort)
                        service = 'set service {name} protocol {protocol} source-port {base}-65535 port {dstPort}'.format(
                            name=serviceName, base=i[5], dstPort=dstPort, protocol=protocol
                        )
                    elif i[8] == 'gt':
                        serviceName = 'AFG-{protocol}-SRC{srcPort}-DST{dstPort}'.format(
                            dstPort=dstPort + '-65535', protocol=protocol, srcPort=i[5] + '-65535').upper()
                        # we have to check to see if the port is in the object database if its a name
                        if not dstPort.isdigit():
                            dstPort = self.checkObjects(object=dstPort)
                        service = 'set service {name} protocol {protocol} source-port {base}-65535 port {dstPort}-65535'.format(
                            name=serviceName, base=i[5], dstPort=dstPort, protocol=protocol
                        )

                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

                # If the source port is gt and the destination port is a range
                elif i[4] == 'gt' and i[8] == 'range':
                    rangeStart = i[9]
                    rangeEnd = i[10]
                    # We should check both range start and end to see if they are object names
                    if not rangeStart.isdigit():
                        rangeStart = self.checkObjects(object=rangeStart)
                    if not rangeEnd.isdigit():
                        rangeEnd = self.checkObjects(object=rangeEnd)

                    # object for service name
                    serviceName = 'AFG-{protocol}-SRC{srcPort}-DST{rangeStart}-{rangeEnd}'.format(
                        rangeStart=rangeStart, rangeEnd=rangeEnd, protocol=protocol, srcPort=i[5] + '-65535').upper()
                    service = 'set service {name} protocol {protocol} source-port {base}-65535 port {rangeStart}-{rangeEnd}'.format(
                        name=serviceName, base=i[5], rangeStart=rangeStart, rangeEnd=rangeEnd, protocol=protocol
                    )
                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

                elif i[4] == 'eq' and i[8] == 'eq':
                    srcPort = i[5]
                    dstPort = i[9]
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)
                    # Need to make sure the source and destination ports are not names
                    if not srcPort.isdigit():
                        srcPort = self.checkObjects(object=srcPort)
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)
                    # object for service name
                    serviceName = 'AFG-{protocol}-SRC{srcPort}-DST{dstPort}'.format(dstPort=dstPort, protocol=protocol, srcPort=srcPort).upper()
                    # we have to check to see if the port is in the object database if its a name
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)

                    service = 'set service {name} protocol {protocol} source-port {srcPort} port {dstPort}'.format(
                        name=serviceName, srcPort=srcPort, dstPort=dstPort, protocol=protocol
                    )
                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

                elif i[4] == 'eq' and i[8] == 'range':
                    srcPort = i[5]
                    # check srcPort to make sure its not an object
                    if not srcPort.isdigit():
                        srcPort = self.checkObjects(object=srcPort)
                    rangeStart = i[9]
                    rangeEnd = i[10]
                    # We should check both range start and end to see if they are object names
                    if not rangeStart.isdigit():
                        rangeStart = self.checkObjects(object=rangeStart)
                    if not rangeEnd.isdigit():
                        rangeEnd = self.checkObjects(object=rangeEnd)

                    # object for service name
                    serviceName = 'AFG-{protocol}-SRC{srcPort}-DST{rangeStart}-{rangeEnd}'.format(
                        rangeStart=rangeStart, rangeEnd=rangeEnd, protocol=protocol, srcPort=srcPort).upper()
                    service = 'set service {name} protocol {protocol} source-port {srcPort} port {rangeStart}-{rangeEnd}'.format(
                        name=serviceName, srcPort=srcPort, rangeStart=rangeStart, rangeEnd=rangeEnd, protocol=protocol
                    )
                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

            # If it wasn't one of the above mixes of either:
            # gt src and eq dst
            # gt src and range dst
            # eq src and eq dst
            # eq src and range dst
            # Then we will assume the src port is missing and we may just be dealing with an eq or range dest port
                elif (self.numPattern.match(i[4]) or i[4] == 'host') and i[6] == 'eq':
                    dstPort = i[7]
                    # Need to verify the port is not an object
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)
                    # object for the service name
                    serviceName = 'AFG-{protocol}-DST{dstPort}'.format(
                        protocol=protocol, dstPort=dstPort).upper()
                    service = 'set service {name} protocol {protocol} port {dstPort}'.format(
                        name=serviceName, protocol=protocol, dstPort=dstPort)
                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

                elif (self.numPattern.match(i[4]) or i[4] == 'host') and i[6] == 'range':
                    dstPort = i[7]
                    # Need to verify the port is not an object
                    if not dstPort.isdigit():
                        dstPort = self.checkObjects(object=dstPort)
                    # object for the service name
                    serviceName = 'AFG-{protocol}-DST{dstPort}'.format(
                        protocol=protocol, dstPort=dstPort)
                    service = 'set service {name} protocol {protocol} port {dstPort}'.format(
                        name=serviceName, protocol=protocol, dstPort=dstPort)
                    # Set the service statement the firewall rule will use
                    serviceStatement = 'service {name}'.format(name=serviceName)

                    # Add the service statement to build to the list as long as it isn't there already
                    if not service in self.servicesToBuild:
                        self.servicesToBuild.append(service)

            # Host section, we use the service in this next step in our rule definition
            try:
                # We've built the possible service objects and service statements above
                # Now we have to look at the host portions of the rules
                if i[2] == 'host':
                    if i[4] == 'host':
                        # if 2 is host then 3 is the host source ip
                        srcIP = i[3]
                        srcMask = '/32'
                        # if 4 is host its a host to host rule
                        # if 4 is host then 5 is the host destination ip
                        dstIP = i[5]
                        # If both are hosts then masks are /32s
                        dstMask = '/32'
                        srcFull = '{host}{mask}'.format(host=srcIP, mask=srcMask)
                        dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                        self.ruleList.append('set rulebase security rules {srcIP}TO{dstIP} from any to any source {src} destination {dst} {serviceStatement} action allow'.format(
                            srcIP=srcIP, dstIP=dstIP, src=srcFull, dst=dstFull, serviceStatement=serviceStatement))
                        self.ruleCounter += 1

                    try:
                        if i[6] == 'host':
                            srcIP = i[3]
                            srcMask = '/32'
                            dstIP = i[7]
                            dstMask = '/32'
                            srcFull = '{host}{mask}'.format(host=srcIP, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcIP}TO{dstIP} from any to any source {src} destination {dst} {serviceStatement} action allow'.format(
                                    srcIP=srcIP, dstIP=dstIP, src=srcFull, dst=dstFull, serviceStatement=serviceStatement))
                            self.ruleCounter += 1
                    except:
                        pass

                    try:
                        # if i[4] is a number and not a host then its a subnet
                        if self.numPattern.match(i[4]):
                            srcIP = i[3]
                            srcMask = '/32'
                            dstIP = i[4]
                            dstMask = self.nettools.subnetToCIDR(i[5])
                            srcFull = '{host}{mask}'.format(host=srcIP, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcIP}TO{dstIP} from any to any source {src} destination {dst} {serviceStatement} action allow'.format(
                                    srcIP=srcIP, dstIP=dstIP, src=srcFull, dst=dstFull, serviceStatement=serviceStatement))
                            self.ruleCounter += 1
                    except:
                        pass

                    try:
                        # if i[6] is a number and not a host then its a subnet
                        if i[6] != 'host':
                            srcIP = i[3]
                            srcMask = '/32'
                            dstIP = i[6]
                            dstMask = self.nettools.subnetToCIDR(i[7])
                            srcFull = '{host}{mask}'.format(host=srcIP, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcIP}TO{dstIP} from any to any source {src} destination {dst} {serviceStatement} action allow'.format(
                                    srcIP=srcIP, dstIP=dstIP, src=srcFull, dst=dstFull,
                                    serviceStatement=serviceStatement))
                            self.ruleCounter += 1
                    except:
                        pass


                # This is the section where we determine if what to do if the source is not a host
                elif i[2] != 'host':

                    # Here we see if i[4] is a host
                    if i[4] == 'host':
                        srcSubnet = i[2]
                        srcMask = self.nettools.subnetToCIDR(i[3])
                        dstIP = i[5]
                        dstMask = '/32'
                        srcFull = '{host}{mask}'.format(host=srcSubnet, mask=srcMask)
                        dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                        self.ruleList.append('set rulebase security rules {srcFull}TO{dstFull} from any to any source {srcFull} destination {dstFull} {serviceStatement} action allow'.format(
                                srcFull=srcFull, dstFull=dstFull, serviceStatement=serviceStatement))
                        self.ruleCounter += 1

                    try:
                        # Try to see if i[6] is a host
                        if i[6] == 'host':
                            srcSubnet = i[2]
                            srcMask = self.nettools.subnetToCIDR(i[3])
                            dstIP = i[7]
                            dstMask = '/32'
                            srcFull = '{host}{mask}'.format(host=srcSubnet, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcFull}TO{dstFull} from any to any source {srcFull} destination {dstFull} {serviceStatement} action allow'.format(
                                    srcFull=srcFull, dstFull=dstFull, serviceStatement=serviceStatement))
                            self.ruleCounter += 1

                    except:
                        pass

                    try:
                        # Lets see if i[4] is a number and not a gt, eq or range
                        if self.numPattern.match(i[4]):
                            srcSubnet = i[2]
                            srcMask = self.nettools.subnetToCIDR(i[3])
                            dstIP = i[4]
                            dstMask = self.nettools.subnetToCIDR(i[5])
                            srcFull = '{host}{mask}'.format(host=srcSubnet, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcFull}TO{dstFull} from any to any source {srcFull} destination {dstFull} {serviceStatement} action allow'.format(
                                    srcFull=srcFull, dstFull=dstFull, serviceStatement=serviceStatement))
                            self.ruleCounter += 1
                    except:
                        pass

                    try:
                        # Finally i[6] if it isn't a host then its a subnet
                        if i[6] != 'host':
                            srcIP = i[3]
                            srcMask = self.nettools.subnetToCIDR(i[4])
                            dstIP = i[6]
                            dstMask = self.nettools.subnetToCIDR(i[7])
                            srcFull = '{host}{mask}'.format(host=srcIP, mask=srcMask)
                            dstFull = '{host}{mask}'.format(host=dstIP, mask=dstMask)
                            self.ruleList.append(
                                'set rulebase security rules {srcFull}TO{dstFull} from any to any source {srcFull} destination {dstFull} {serviceStatement} action allow'.format(
                                    srcFull=srcFull, dstFull=dstFull,
                                    serviceStatement=serviceStatement))
                            self.ruleCounter += 1
                    except:
                        pass

                # If nothing matched...
                else:
                    print('this rule matched no conditions {i}'.format(i=i))


            except Exception as e:
                print(i)
                print(e)
                pass

    def printServices(self):
        # Prints out services referenced in the rules
        self.printSpacer()
        for i in self.servicesToBuild:
            print(i)

    def printRules(self):
        # Prints out unsorted rules
        self.printSpacer()
        for i in self.ruleList:
            print(i)

    def printRuleTotal(self):
        # Prints out count of rules
        self.printSpacer()
        print('Total count of generated rules = {count}'.format(count=self.ruleCounter))


    def compressRules(self):
        '''
        Will create an instance of rulecompression.py's RuleCompression and return the new list
        :return: finalList
        '''
        # Create an instance of rule compression and send the rulelist
        compressedRules = RuleCompression(self.ruleList)
        # Trigger the aggregation of rules
        compressedRules.compressBySourceIPandDestPort(changeNumber=self.changeNumber)
        # Return the aggregated rule list
        finalList = compressedRules.returnRules()
        return finalList

    def sortRulesByName(self, rulelist):
        '''
        Takes a list of lists and sorts them based on index 4 for rule name
        :param rulelist: the list of rule lists
        :return: sortedList
        '''
        sortedList = sorted(rulelist, key=itemgetter(4))
        return sortedList



# Testing, only runs if this file is called directly and not if called from another project or file
if __name__ == '__main__':
    test = Normalization()
    test.normalizeFile()
    test.generateRules()
    #test.printServices()
    #test.printRuleTotal()
    newList = test.compressRules()
    # get a sorted list just in case you want to see that too
    sortedNewList = test.sortRulesByName(newList)
    # The below output will make each rule(list) a single string easy for copying
    for i in sortedNewList:
        # Print out the rule
        print(' '.join(i))
        pass