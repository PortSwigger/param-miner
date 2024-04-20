package burp.model.utilities.burp;

import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.model.utilities.misc.Utilities;

import java.net.URL;
import java.util.Arrays;
import java.util.List;

public class LazyRequestInfo implements IRequestInfo {
public LazyRequestInfo(byte[] request, IHttpService service) {
  this.request = request;
  this.service = service;
}

public String getMethod() {
  if(this.method == null) {
    this.method = Utilities.getMethod(this.request);
  }
  
  return this.method;
}

public URL getUrl() {
  if(this.url == null) {
    if(this.service == null) {
      throw new RuntimeException("Can't get URL from request with no service");
    }
    
    this.url = Utilities.getURL(this.request, this.service);
  }
  
  return this.url;
}

public List<String> getHeaders() {
  if(this.headers == null) {
    this.headers = Arrays.asList(Utilities.getHeaders(this.request).split("\r\n"));
  }
  
  return this.headers;
}

public List<IParameter> getParameters() {
  throw new RuntimeException("getParameters is not implemented");
}

public int getBodyOffset() {
  return Utilities.getBodyStart(this.request);
}

public byte getContentType() {
  throw new RuntimeException("getContentType is not implemented");
}
final byte[] request;
List<String> headers = null;
String       method  = null;
URL          url     = null;
IHttpService service = null;
}

