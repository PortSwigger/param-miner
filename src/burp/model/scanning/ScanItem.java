package burp.model.scanning;

import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IResponseInfo;
import burp.IScannerInsertionPoint;
import burp.albinowaxUtils.ParamInsertionPoint;
import burp.albinowaxUtils.RawInsertionPoint;
import burp.albinowaxUtils.Req;
import burp.view.ConfigurableSettings;

import java.util.ArrayList;
import java.util.Iterator;

public class ScanItem {
private final burp.Utilities utilities;
private Scan                 scan;
public  IHttpRequestResponse req;
public  String               host;
private ConfigurableSettings config;
private boolean              prepared = false;
IScannerInsertionPoint insertionPoint;
private IParameter param;
private String     key = null;
String method = null;

ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, burp.Utilities utilities) {
  this.utilities = utilities;
  this.req = req;
  this.host = req.getHttpService().getHost();
  this.config = config;
  this.scan = scan;
}

ScanItem(burp.Utilities utilities, IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param, IScannerInsertionPoint insertionPoint) {
  this.utilities      = utilities;
  this.req            = req;
  this.config         = config;
  this.scan           = scan;
  this.insertionPoint = insertionPoint;
  this.host           = req.getHttpService().getHost();
  this.prepared       = true;
  this.param          = param;
}

ScanItem(burp.Utilities utilities, IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param) {
  this.utilities      = utilities;
  this.req            = req;
  this.host           = req.getHttpService().getHost();
  this.config         = config;
  this.param          = param;
  this.insertionPoint = new RawInsertionPoint(req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd());
  this.prepared       = true;
  this.scan           = scan;
}

boolean prepared() {
  return this.prepared;
}

ArrayList<ScanItem> prepare() {
  ArrayList<ScanItem> items = new ArrayList();
  this.method = utilities.getMethod(this.req.getRequest());
  this.prepared = true;
  if (utilities.containsBytes(this.req.getResponse(), "HTTP/2".getBytes())) {
    byte[] updated;
    Req    newReq;
    if (utilities.globalSettings.getBoolean("params: scheme")) {
      updated = utilities.addOrReplaceHeader(this.req.getRequest(), ":scheme", "m838jacxka");
      newReq = new Req(updated, this.req.getResponse(), this.req.getHttpService());
      items.add(new ScanItem(utilities, newReq, this.config, this.scan, utilities.paramify(updated, "scheme-proto", "m838jacxka", "https")));
    }
    
    if (utilities.globalSettings.getBoolean("params: scheme-path")) {
      updated = utilities.addOrReplaceHeader(this.req.getRequest(), ":scheme", "https://" + this.req.getHttpService().getHost() + "/m838jacxka");
      newReq = new Req(updated, this.req.getResponse(), this.req.getHttpService());
      items.add(new ScanItem(utilities, newReq, this.config, this.scan, utilities.paramify(updated, "scheme-path", "m838jacxka", "m838jacxka")));
    }
    
    if (utilities.globalSettings.getBoolean("params: scheme-host")) {
      updated = utilities.addOrReplaceHeader(this.req.getRequest(), ":scheme", "https://m838jacxka/");
      newReq = new Req(updated, this.req.getResponse(), this.req.getHttpService());
      items.add(new ScanItem(utilities, newReq, this.config, this.scan, utilities.paramify(updated, "scheme-host", "m838jacxka", "m838jacxka")));
    }
  }
  
  boolean cookiesToScan = utilities.globalSettings.getBoolean("params: cookie") && !"".equals(
    utilities.getHeader(this.req.getRequest(), "Cookie"));
  boolean bodyToScan = utilities.globalSettings.getBoolean("params: body") && !"".equals(utilities.getBody(this.req.getRequest()));
  ArrayList params;
  Iterator var5;
  IParameter param;
  if (cookiesToScan || bodyToScan) {
    params = new ArrayList(utilities.helpers.analyzeRequest(this.req).getParameters());
    var5 = params.iterator();

label72:
    while(true) {
label70:
      while(true) {
        if (!var5.hasNext()) {
          break label72;
        }
        
        param = (IParameter)var5.next();
        byte type = param.getType();
        switch (type) {
        case 1:
          if (bodyToScan) {
            break label70;
          }
          break;
        case 2:
          if (cookiesToScan) {
            break label70;
          }
        }
      }
      
      IScannerInsertionPoint insertionPoint = new ParamInsertionPoint(this.req.getRequest(), param, utilities);
      items.add(new ScanItem(utilities, this.req, this.config, this.scan, param, insertionPoint));
    }
  }
  
  if (!utilities.globalSettings.getBoolean("params: query")) {
    return items;
  } else if (!utilities.getPathFromRequest(this.req.getRequest()).contains("=") && !utilities.globalSettings.getBoolean("params: dummy")) {
    return items;
  } else {
    if (utilities.globalSettings.getBoolean("params: dummy")) {
      this.req = new Req(utilities.appendToQuery(this.req.getRequest(), utilities.globalSettings.getString("dummy param name") + "=z"), this.req.getResponse(), this.req.getHttpService());
    }
    
    params = utilities.getQueryParams(this.req.getRequest());
    var5 = params.iterator();
    
    while(var5.hasNext()) {
      param = (IParameter)var5.next();
      if (param.getType() == 0) {
        items.add(new ScanItem(utilities, this.req, this.config, this.scan, param));
      }
    }
    
    return items;
  }
}

String getKey() {
  if (this.method == null) {
    this.method = utilities.getMethod(this.req.getRequest());
  }
  
  if (this.key != null) {
    return this.key;
  } else {
    StringBuilder key = new StringBuilder();
    if (!this.config.getBoolean("filter HTTP")) {
      key.append(this.req.getHttpService().getProtocol());
    }
    
    key.append(this.req.getHttpService().getHost());
    if (this.scan instanceof ParamScan && this.config.getBoolean("key input name")) {
      key.append(this.param.getName());
      key.append(this.param.getType());
    }
    
    if (this.config.getBoolean("key method")) {
      key.append(this.method);
    }
    
    if (this.config.getBoolean("key path")) {
      key.append(utilities.getPathFromRequest(this.req.getRequest()).split("[?]", 1)[0]);
    }
    
    if (this.req.getResponse() == null && this.config.getBoolean("key content-type")) {
      key.append(utilities.getExtension(this.req.getRequest()));
    }
    
    if (this.req.getResponse() != null && (this.config.getBoolean("key header names") || this.config.getBoolean("key status") || this.config.getBoolean("key content-type") || this.config.getBoolean("key server"))) {
      IResponseInfo respInfo = utilities.helpers.analyzeResponse(this.req.getResponse());
      if (this.config.getBoolean("key header names")) {
        StringBuilder headerNames = new StringBuilder();
        Iterator var4 = respInfo.getHeaders().iterator();
        
        while(var4.hasNext()) {
          String header = (String)var4.next();
          headerNames.append(header.split(": ")[0]);
        }
        
        key.append(headerNames.toString());
      }
      
      if (this.config.getBoolean("key status")) {
        key.append(respInfo.getStatusCode());
      }
      
      if (this.config.getBoolean("key content-type")) {
        key.append(respInfo.getStatedMimeType());
      }
      
      if (this.config.getBoolean("key server")) {
        key.append(utilities.getHeader(this.req.getResponse(), "Server"));
      }
    }
    
    this.key = key.toString();
    return this.key;
  }
}
}