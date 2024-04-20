package burp.model.utilities.burp;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {
private final IHttpService httpService;
private final URL          url;
private final IHttpRequestResponse[] httpMessages;
private final String                 name;
private final String                 detail;
private final String severity;
private final String confidence;
private final String remediation;

public CustomScanIssue(
  IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity,
  String confidence, String remediation
) {
  this.name = name;
  this.detail = detail;
  this.severity = severity;
  this.httpService = httpService;
  this.url = url;
  this.httpMessages = httpMessages;
  this.confidence = confidence;
  this.remediation = remediation;
}

CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse httpMessages, String name, String detail, String severity, String confidence, String remediation) {
                         this.name = name;
                         this.detail = detail;
                         this.severity = severity;
                         this.httpService = httpService;
                         this.url = url;
                         this.httpMessages = new IHttpRequestResponse[1];
  this.httpMessages[0] = httpMessages;
                         this.confidence = confidence;
                         this.remediation = remediation;
}

public URL getUrl() {
  return this.url;
}

public String getIssueName() {
  return this.name;
}

public int getIssueType() {
  return 0;
}

public String getSeverity() {
  return this.severity;
}

public String getConfidence() {
  return this.confidence;
}

public String getIssueBackground() {
  return null;
}

public String getRemediationBackground() {
  return null;
}

public String getIssueDetail() {
  return this.detail;
}

public String getRemediationDetail() {
  return this.remediation;
}

public IHttpRequestResponse[] getHttpMessages() {
  return this.httpMessages;
}

public IHttpService getHttpService() {
  return this.httpService;
}

public String getHost() {
  return null;
}

public int getPort() {
  return 0;
}

public String getProtocol() {
  return null;
}
}

