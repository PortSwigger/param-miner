package burp.albinowaxUtils;

import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.IResponseVariations;
import burp.Utilities;

import java.util.Arrays;

public class Resp {
private IHttpRequestResponse req;
private IResponseInfo        info;
private IResponseVariations  attributes;
private long                 timestamp;
private long responseTime;
private short status;
private boolean timedOut;
private boolean failed;
private boolean early;
private final Utilities utilities;

public long getTimestamp() {
  return this.timestamp;
}

public long getResponseTime() {
  return this.responseTime;
}

public short getStatus() {
  return this.status;
}

public Resp(IHttpRequestResponse req, Utilities utilities) {
  this(req, System.currentTimeMillis(), utilities);
}

public Resp(IHttpRequestResponse req, long startTime, Utilities utilities) {
  this.utilities    = utilities;
  this.timestamp    = 0L;
  this.responseTime = 0L;
  this.status       = 0;
  this.timedOut     = false;
  this.failed       = false;
  this.early        = false;
  this.req          = req;
  byte[] fail = utilities.helpers.stringToBytes("null");
  byte[] earlyResponse = utilities.helpers.stringToBytes("early-response");
  int burpTimeout = Integer.parseInt(utilities.getSetting("project_options.connections.timeouts.normal_timeout"));
  int scanTimeout = utilities.globalSettings.getInt("timeout") * 1000;
  this.early = Arrays.equals(req.getResponse(), earlyResponse);
  this.failed = req.getResponse() == null || req.getResponse().length == 0 || Arrays.equals(req.getResponse(), fail) || this.early;
  this.responseTime = System.currentTimeMillis() - startTime;
  if (burpTimeout == scanTimeout) {
    if (this.failed && this.responseTime > (long)scanTimeout) {
      this.timedOut = true;
    }
  } else if (this.responseTime > (long)scanTimeout) {
    this.timedOut = true;
    if (this.failed) {
      utilities.out("TImeout with response. Start time: " + startTime + " Current time: " + System.currentTimeMillis() + " Difference: " + (System.currentTimeMillis() - startTime) + " Tolerance: " + scanTimeout);
    }
  }
  
  if (!this.failed) {
    this.info = utilities.helpers.analyzeResponse(req.getResponse());
    this.attributes = utilities.helpers.analyzeResponseVariations(new byte[][]{req.getResponse()});
    this.status = this.info.getStatusCode();
  }
  
  this.timestamp = System.currentTimeMillis();
}

public IHttpRequestResponse getReq() {
  return this.req;
}

IResponseInfo getInfo() {
  return this.info;
}

IResponseVariations getAttributes() {
  return this.attributes;
}

public boolean early() {
  return this.early;
}

public boolean failed() {
  return this.failed || this.timedOut;
}

public boolean timedOut() {
  return this.timedOut;
}
}
