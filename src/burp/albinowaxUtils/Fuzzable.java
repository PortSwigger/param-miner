package burp.albinowaxUtils;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import burp.Utilities;
import org.apache.commons.lang3.ArrayUtils;

public class Fuzzable extends CustomScanIssue {
private static final String REMEDIATION = "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. Try to determine the root cause of the observed behaviour.Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ";

public Fuzzable(
  IHttpRequestResponse[] requests, IHttpRequestResponse baseRequestResponse, String title, String detail,
  boolean reliable, String severity,
  Utilities utilities
) {
  super(requests[0].getHttpService(), utilities.helpers.analyzeRequest(baseRequestResponse).getUrl(), (IHttpRequestResponse[])ArrayUtils.add(requests, 0, baseRequestResponse), title, detail, severity, calculateConfidence(reliable), "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. Try to determine the root cause of the observed behaviour.Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ");
}

private static String calculateConfidence(boolean reliable) {
  String confidence = "Tentative";
  if (reliable) {
    confidence = "Firm";
  }
  
  return confidence;
}
}
