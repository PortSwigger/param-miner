package burp.albinowaxUtils;

import burp.IHttpRequestResponse;
import burp.IResponseKeywords;
import burp.IResponseVariations;
import burp.Probe;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class Attack {
static final int UNINITIALISED = -1;
static final int DYNAMIC = -2;
static final int                     INCALCULABLE = -3;
private      IHttpRequestResponse    firstRequest;
private      HashMap<String, Object> firstFingerprint;
private HashMap<String, Object> lastPrint;
private IHttpRequestResponse lastRequest;
private String[] keys;
public  String   payload;
private Probe    probe;
private String                  anchor;
private HashMap<String, Object> fingerprint;
private IResponseKeywords       responseKeywords;
private IResponseVariations     responseDetails;
private int                     responseReflections;
private final Utilities utilities;

public HashMap<String, Object> getLastPrint() {
  return this.lastPrint;
}

public IHttpRequestResponse getLastRequest() {
  return this.lastRequest;
}

public Attack(IHttpRequestResponse req, Probe probe, String payload, String anchor, Utilities utilities) {
  this.utilities           = utilities;
  this.keys                = new String[]{utilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};
  this.responseKeywords    = utilities.helpers.analyzeResponseKeywords(Arrays.asList(this.keys), new byte[0][]);
  this.responseDetails     = utilities.helpers.analyzeResponseVariations(new byte[0][]);
  this.responseReflections = -1;
  this.firstRequest        = req;
  this.lastRequest         = req;
  this.probe               = probe;
  this.payload             = payload;
  this.anchor              = anchor;
  this.add(req.getResponse(), anchor);
  this.firstFingerprint = this.fingerprint;
  this.lastPrint = this.fingerprint;
}

public Attack(IHttpRequestResponse req, Utilities utilities) {
  this.utilities           = utilities;
  this.keys                = new String[]{utilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};
  this.responseKeywords    = utilities.helpers.analyzeResponseKeywords(Arrays.asList(this.keys), new byte[0][]);
  this.responseDetails     = utilities.helpers.analyzeResponseVariations(new byte[0][]);
  this.responseReflections = -1;
  this.firstRequest        = req;
  this.lastRequest         = req;
  this.add(req.getResponse(), "");
  this.firstFingerprint = this.fingerprint;
  this.lastPrint = this.fingerprint;
}

public Attack(Utilities utilities) {
  this.utilities           = utilities;
  this.keys                = new String[]{utilities.globalSettings.getString("canary"), "\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div"};
  this.responseKeywords    = utilities.helpers.analyzeResponseKeywords(Arrays.asList(this.keys), new byte[0][]);
  this.responseDetails     = utilities.helpers.analyzeResponseVariations(new byte[0][]);
  this.responseReflections = -1;
}

public HashMap<String, Object> getPrint() {
  return this.fingerprint;
}

public HashMap<String, Object> getFirstPrint() {
  return this.firstFingerprint;
}

public IHttpRequestResponse getFirstRequest() {
  return this.firstRequest;
}

private void regeneratePrint() {
  HashMap<String, Object> generatedPrint = new HashMap();
  List<String> keys = this.responseKeywords.getInvariantKeywords();
  Iterator var3 = keys.iterator();
  
  String key;
  while(var3.hasNext()) {
    key = (String)var3.next();
    generatedPrint.put(key, this.responseKeywords.getKeywordCount(key, 0));
  }
  
  keys = this.responseDetails.getInvariantAttributes();
  var3 = keys.iterator();
  
  while(var3.hasNext()) {
    key = (String)var3.next();
    generatedPrint.put(key, this.responseDetails.getAttributeValue(key, 0));
  }
  
  if (this.responseReflections != -2) {
    generatedPrint.put("input_reflections", this.responseReflections);
  }
  
  this.fingerprint = generatedPrint;
}

public Probe getProbe() {
  return this.probe;
}

private Attack add(byte[] response, String anchor) {
  assert this.firstRequest != null;
  
  response = utilities.filterResponse(response);
  this.responseKeywords.updateWith(new byte[][]{response});
  this.responseDetails.updateWith(new byte[][]{response});
  if (anchor.equals("")) {
    this.responseReflections = -3;
  } else {
    int reflections = utilities.countMatches(response, anchor.getBytes());
    if (this.responseReflections == -1) {
      this.responseReflections = reflections;
    } else if (this.responseReflections != reflections && this.responseReflections != -3) {
      this.responseReflections = -2;
    }
  }
  
  this.regeneratePrint();
  return this;
}

public Attack addAttack(Attack attack) {
  if (this.firstRequest == null) {
    this.firstRequest = attack.firstRequest;
    this.anchor = attack.anchor;
    this.probe = attack.getProbe();
    this.payload = attack.payload;
    this.add(attack.getFirstRequest().getResponse(), this.anchor);
    this.firstFingerprint = this.fingerprint;
  }
  
  HashMap<String, Object> generatedPrint = new HashMap();
  HashMap<String, Object> inputPrint = attack.getPrint();
  Iterator var4 = inputPrint.keySet().iterator();
  
  while(var4.hasNext()) {
    String key = (String)var4.next();
    if (this.fingerprint.containsKey(key) && this.fingerprint.get(key).equals(inputPrint.get(key))) {
      generatedPrint.put(key, this.fingerprint.get(key));
    }
  }
  
  this.fingerprint = generatedPrint;
  this.lastRequest = attack.lastRequest;
  this.lastPrint = attack.getPrint();
  return this;
}
}

