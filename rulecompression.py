# This file should take firewall rules, and condense them into an efficient format
# Things such as a single host going to a single dest port to multiple hosts
# making those all one rule vs 2 or more

class RuleCompression:

    def __init__(self, rulelist):
        '''
        :param rulelist: a list full of lists of rules to use
        '''
        self.rulelist = rulelist
        # This list will be used to store the end values
        self.finalList = []
        # Need a list to store a split rule list in
        self.splitRulelist = []


    def compressBySourceIPandDestPort(self, changeNumber=''):
        # change number is referenced in the rulename, we have to keep it below 31 characters
        # the counter will get appended to the end of the rule number
        ruleNameCounter = 1
        # We're going to edit the list so we need to make a copy to work with here
        # We split the ruleset into a list of lists to use
        for i in self.rulelist:
            self.splitRulelist.append(i.split())
        # Useful info, index 4 is the service name, 10 is source ip/network and 14 is destination ip/network

        # The simplest way I could think to do this at the time is to combine the src IP and the service
        # Object used and put into the rulename, this makes any source going to a service have the same rule
        # name which will add the destinations to the rule
        for i in self.splitRulelist:
            rulenameNew = 'src-{src}-tosrv-{service}'.format(src=i[10], service=i[14]).upper()
            # now change the service name in the rule
            i[4] = rulenameNew
            # append the new rules to the finalList ruleset
            self.finalList.append(i)

        # gotta rewrite the rule names because they are too long for PAN....
        tempList = []
        for i in self.finalList:
            if i[4] not in tempList:
                tempList.append(i[4])

        # Now we'll take all those rule names from templist, generate a change name and append an incrementing number
        for i in tempList:
            newRuleName = ''.join((changeNumber, '-', str(ruleNameCounter)))
            # gotta loop through the finalList....this can probably be done more efficiently so look into that
            for index, j in enumerate(self.finalList):
                if j[4] == i:
                    self.finalList[index][4] = newRuleName
            ruleNameCounter += 1




    def returnRules(self):
        '''
        Returns the new ruleset
        :return: self.finalList
        '''
        return self.finalList