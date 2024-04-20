//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.model.scanning;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.model.utilities.burp.CustomScanIssue;
import burp.model.utilities.burp.Req;
import burp.model.utilities.scan.Resp;
import burp.model.utilities.misc.Utilities;
import burp.view.SettingsBox;
import org.apache.commons.lang3.NotImplementedException;

public abstract class Scan implements IScannerCheck {
String      name = "";
public final    SettingsBox scanSettings;
protected final Utilities   utilities;
protected final BulkScanLauncher launcher;

public Scan(String name, Utilities utilities, BulkScanLauncher launcher) {
  this.name      = name;
  this.utilities = utilities;
  this.launcher  = launcher;
  BulkScan.scans.add(this);
  this.scanSettings = new SettingsBox(utilities);
  this.scanSettings.register("thread pool size", 8, "The maximum number of threads created for attacks. This roughly equates to the number of concurrent HTTP requests. Increase this number to make large scale attacks go faster, or decrease it to reduce your system load.");
  this.scanSettings.register("use key", true, "Avoid scanning similar endpoints by generating a key from each request's hostname and protocol, and skipping subsequent requests with matching keys.");
  this.scanSettings.register("key method", true, "Include the request method in the key");
  this.scanSettings.register("key path", false, "Include the request path in the key");
  this.scanSettings.register("key status", true, "Include the response status code in the key");
  this.scanSettings.register("key content-type", true, "Include the response content-type in the key");
  this.scanSettings.register("key server", true, "Include the response Server header in the key");
  this.scanSettings.register("key input name", true, "Include the name of the parameter being scanned in the key");
  this.scanSettings.register("key header names", false, "Include all response header names (but not values) in the key");
  this.scanSettings.register("filter", "", "Only scan requests containing the configured string");
  this.scanSettings.register("mimetype-filter", "", "Only scan responses with the configured string in their mimetype");
  this.scanSettings.register("resp-filter", "", "Only scan requests with responses containing the configured string.");
  this.scanSettings.register("filter HTTP", false, "Only scan HTTPS requests");
  this.scanSettings.register("timeout", 10, "The time after quick a response is considered to have timed out. Tweak with caution, and be sure to adjust Burp's request timeout to match.");
  this.scanSettings.register("skip vulnerable hosts", false, "Don't scan hosts already flagged as vulnerable during this scan. Reload the extension to clear flags.");
  this.scanSettings.register("skip flagged hosts", false, "Don't report issues on hosts already flagged as vulnerable");
  this.scanSettings.register("flag new domains", false, "Adjust the title of issues reported on hosts that don't have any other issues listed in the sitemap");
  this.scanSettings.register("confirmations", 5, "The number of repeats used to confirm behaviour is consistent. Increase this to reduce false positives caused by random noise");
  this.scanSettings.register("report tentative", true, "Report less reliable isssues (only relevant to Backslash Powered Scanner?)");
  this.scanSettings.register("include origin in cachebusters", true);
  this.scanSettings.register("include path in cachebusters", false);
}

public List<String> getSettings() {
  return this.scanSettings.getSettings();
}

public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
  throw new RuntimeException("doScan(byte[] baseReq, IHttpService service) invoked but not implemented");
}

public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
  return this.doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
}

public boolean shouldScan(IHttpRequestResponse baseRequestResponse) {
  return !utilities.globalSettings.getBoolean("skip vulnerable hosts") || !BulkScan.hostsToSkip.containsKey(baseRequestResponse.getHttpService().getHost());
}

public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
  return this.doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
}

public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
  return null;
}

public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
  return 0;
}

public void recordCandidateFound() {
  launcher.getTaskEngine().candidates.incrementAndGet();
}

public static void report(String title, String detail, Utilities utilities, Resp... requests) {
  report(title, detail, null, utilities, requests);
}

public static  void report(String title, String detail, byte[] baseBytes, Utilities utilities, Resp... requests) {
  IHttpRequestResponse base = requests[0].getReq();
  IHttpService service = base.getHttpService();
  ArrayList<IHttpRequestResponse> reqsToReport = new ArrayList();
  if (!utilities.globalSettings.getBoolean("skip flagged hosts") || !BulkScan.domainAlreadyFlagged(service, utilities)) {
    if (utilities.globalSettings.getBoolean("flag new domains") && !BulkScan.domainAlreadyFlagged(service, utilities)) {
      title = "NEW| " + title;
    }
    
    if (baseBytes != null) {
      Resp baseReq = new Resp(new Req(baseBytes, null, service), utilities);
      reqsToReport.add(baseReq.getReq());
    }
    
    Resp[] var11 = requests;
    int var8 = requests.length;
    
    for(int var9 = 0; var9 < var8; ++var9) {
      Resp request = var11[var9];
      reqsToReport.add(request.getReq());
    }
    
    if (utilities.isBurpPro()) {
      utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service),
        reqsToReport.toArray(new IHttpRequestResponse[0]), title, detail, "High", "Tentative", "."));
    } else {
      StringBuilder serialisedIssue = new StringBuilder();
      serialisedIssue.append("Found issue: ");
      serialisedIssue.append(title);
      serialisedIssue.append("\n");
      serialisedIssue.append("Target: ");
      serialisedIssue.append(service.getProtocol());
      serialisedIssue.append("://");
      serialisedIssue.append(service.getHost());
      serialisedIssue.append("\n");
      serialisedIssue.append(detail);
      serialisedIssue.append("\n");
      serialisedIssue.append("Evidence: \n======================================\n");
      Iterator var13 = reqsToReport.iterator();
      
      while(var13.hasNext()) {
        IHttpRequestResponse req = (IHttpRequestResponse)var13.next();
        serialisedIssue.append(utilities.helpers.bytesToString(req.getRequest()));
        serialisedIssue.append("\n======================================\n");
      }
      
      utilities.out(serialisedIssue.toString());
    }
    
  }
}

public static Resp request(IHttpService service, byte[] req, Utilities utilities) {
  return request(service, req, 0, utilities);
}

public static Resp request(IHttpService service, byte[] req, int maxRetries, Utilities utilities) {
  return request(service, req, maxRetries, false, utilities);
}

public static Resp request(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1, Utilities utilities) {
  return request(service, req, maxRetries, forceHTTP1, null, utilities);
}

public static Resp request(
  IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1, HashMap<String, Boolean> config,
  Utilities utilities
) {
  if (utilities.unloaded.get()) {
    throw new RuntimeException("Aborting due to extension unload");
  } else {
    IHttpRequestResponse resp = null;
    utilities.requestCount.incrementAndGet();
    long startTime = System.currentTimeMillis();
    int attempts = 0;
    
    while((resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
      startTime = System.currentTimeMillis();
      
      try {
        if (forceHTTP1 || !utilities.supportsHTTP2) {
          req = utilities.replaceFirst(req, "HTTP/2\r\n", "HTTP/1.1\r\n");
        }
        
        byte[] responseBytes;
        if (utilities.supportsHTTP2) {
          responseBytes = utilities.callbacks.makeHttpRequest(service, req, forceHTTP1).getResponse();
        } else {
          responseBytes = utilities.callbacks.makeHttpRequest(service, req).getResponse();
        }
        
        resp = new Req(req, responseBytes, service);
      } catch (NoSuchMethodError var10) {
        utilities.supportsHTTP2 = false;
        continue;
      } catch (RuntimeException var11) {
        utilities.out("Recovering from request exception: " + service.getHost());
        utilities.err("Recovering from request exception: " + service.getHost());
        resp = new Req(req, null, service);
      }
      
      ++attempts;
    }
    
    return new Resp(resp, startTime, utilities);
  }
}
}
