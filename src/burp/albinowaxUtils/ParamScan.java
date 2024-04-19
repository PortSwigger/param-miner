//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.Utilities;

import java.util.List;

public abstract class ParamScan extends Scan {
public ParamScan(String name, Utilities utilities, BulkScanLauncher launcher) {
  super(name, utilities, launcher);
  this.scanSettings.register("params: dummy", false, "When doing a parameter-based scan, add a dummy parameter to every request");
  this.scanSettings.register("dummy param name", "utm_campaign");
  this.scanSettings.register("params: query", true, "When doing a parameter-based scan, scan query params");
  this.scanSettings.register("params: body", true, "When doing a parameter-based scan, scan body params");
  this.scanSettings.register("params: cookie", false, "When doing a parameter-based scan, scan cookies");
  this.scanSettings.register("params: scheme", false, "When doing a parameter-based scan over HTTP/2, scan the :scheme header");
  this.scanSettings.register("params: scheme-host", false, "When doing a parameter-based scan over HTTP/2, create a fake host in the :scheme header and scan it");
  this.scanSettings.register("params: scheme-path", false, "When doing a parameter-based scan over HTTP/2, create a fake path in the :scheme header and scan it");
}

public abstract List<IScanIssue> doScan(IHttpRequestResponse var1, IScannerInsertionPoint var2);

public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
  return this.doScan(baseRequestResponse, insertionPoint);
}

public abstract List<IScanIssue> doScan(byte[] baseReq, IHttpService service);
}
