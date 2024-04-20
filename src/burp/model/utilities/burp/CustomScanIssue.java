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

@Override
public URL getUrl() {
  return this.url;
}

@Override
public String getIssueName() {
  return this.name;
}

@Override
public int getIssueType() {
  return 0;
}

@Override
public String getSeverity() {
  return this.severity;
}

@Override
public String getConfidence() {
  return this.confidence;
}

@Override
public String getIssueBackground() {
  return null;
}

@Override
public String getRemediationBackground() {
  return null;
}

@Override
public String getIssueDetail() {
  return this.detail;
}

@Override
public String getRemediationDetail() {
  return this.remediation;
}

@Override
public IHttpRequestResponse[] getHttpMessages() {
  return this.httpMessages;
}

@Override
public IHttpService getHttpService() {
  return this.httpService;
}

}
