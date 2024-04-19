package burp.albinowaxUtils;

import burp.IHttpRequestResponsePersisted;
import burp.Utilities;

public class BulkScanItem implements Runnable {
private final ScanItem                      baseItem;
private final IHttpRequestResponsePersisted baseReq;
private final Scan                          scanner;
private final long                          start;
private final Utilities utilities;
private final BulkScanLauncher luancher;

BulkScanItem(Scan scanner, ScanItem baseReq, long start, Utilities utilities, BulkScanLauncher luancher) {
  this.luancher  = luancher;
  this.baseReq   = utilities.callbacks.saveBuffersToTempFiles(baseReq.req);
  this.baseItem  = baseReq;
  this.scanner   = scanner;
  this.start     = start;
  this.utilities = utilities;
}

public void run() {
  try {
    if(this.scanner.shouldScan(this.baseReq)) {
      if(this.scanner instanceof ParamScan) {
        this.scanner.doActiveScan(this.baseReq, this.baseItem.insertionPoint);
      }
      else {
        this.scanner.doScan(this.baseReq);
      }
    }
    else {
      utilities.out("Skipping already-confirmed-vulnerable host: " + this.baseItem.host);
    }
    
    ScanPool engine = luancher.getTaskEngine();
    long     done   = engine.getCompletedTaskCount() + 1L;
    utilities.out("Completed request with key " + this.baseItem.getKey() + ": " + done + " of " +
      ((long) engine.getQueue().size() + done) + " in " + (System.currentTimeMillis() - this.start) / 1000L +
      " seconds with " + utilities.requestCount.get() + " requests, " + engine.candidates + " candidates and " +
      engine.findings + " findings ");
  }
  catch(Exception e) {
    utilities.showError(e);
  }
}

}