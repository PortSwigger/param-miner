package burp.model.insertionPoints;

import burp.model.utilities.misc.Utilities;

import java.util.ArrayList;
import java.util.Iterator;

public class HeaderNameInsertionPoint extends ParamNameInsertionPoint {

public HeaderNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID, Utilities utilities) {
  super(request, name, value, type, attackID, utilities);
}

public byte[] buildBulkRequest(ArrayList<String> params) {
  String           merged    = prepBulkParams(params);
  Iterator<String> dupeCheck = params.iterator();
  byte[]           body      = utilities.getBodyBytes(request);
  
  boolean fooReq = false;
  if (utilities.containsBytes(body, "FOO BAR AAH\r\n".getBytes())) {
    fooReq = true;
  }
  
  if (fooReq || utilities.containsBytes(body, " HTTP/1.1\r\n".getBytes())) {
    utilities.chopNestedResponses = true;
    
    boolean usingCorrectContentLength = true;
    
    try {
      if (body.length != Integer.parseInt(utilities.getHeader(request, "Content-Length"))) {
        usingCorrectContentLength = false;
      }
    } catch (Exception e) {
    
    }
    
    while (dupeCheck.hasNext()) {
      String param = dupeCheck.next().split("~", 2)[0];
      byte[] toReplace = ("\n"+param+": ").getBytes();
      if (utilities.containsBytes(body, toReplace)) {
        body = utilities.replace(body, toReplace, ("\nold"+param+": ").getBytes());
      }
    }
    
    byte[] newBody;
    if (fooReq) {
      newBody = utilities.replaceFirst(body, "FOO BAR AAH\r\n", "GET http://"+utilities.getHeader(request, "Host")+"/ HTTP/1.1\r\n"+merged+"\r\n");
    }
    else {
      newBody = utilities.replaceFirst(body, "HTTP/1.1", "HTTP/1.1\r\n"+merged);
    }
    
    byte[] finalRequest = utilities.setBody(request, new String(newBody));
    if (usingCorrectContentLength) {
      finalRequest = Utilities.fixContentLength(finalRequest);
    }
    
    finalRequest = utilities.addOrReplaceHeader(finalRequest, "X-Mine-Nested-Request", "1");
    
    return finalRequest;
  }
  
  String replaceKey = "TCZqBcS13SA8QRCpW";
  byte[] built = utilities.addOrReplaceHeader(request, replaceKey, "foo");
  
  if (params.isEmpty() || "".equals(merged)) {
    return built;
  }
  
  while (dupeCheck.hasNext()) {
    String param = dupeCheck.next().split("~", 2)[0];
    if (present.containsKey(param)) {
      String toReplace = present.get(param)+": ";
      built = utilities.replace(built, toReplace.getBytes(), ("old"+toReplace).getBytes());
    }
  }
  
  return utilities.setHeader(built, replaceKey, "x\r\n"+merged);
}
}

