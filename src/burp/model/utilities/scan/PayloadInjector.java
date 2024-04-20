//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.model.utilities.scan;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScannerInsertionPoint;
import burp.model.scanning.guessing.header.HeaderMutator;
import burp.model.utilities.misc.Utilities;

import java.io.IOException;
import java.util.ArrayList;

public class PayloadInjector {
private final Utilities    utilities;
private       IHttpService service;
private IScannerInsertionPoint insertionPoint;
private IHttpRequestResponse   base;

public IHttpService getService() {
  return this.service;
}

public IScannerInsertionPoint getInsertionPoint() {
  return this.insertionPoint;
}

public IHttpRequestResponse getBase() {
  return this.base;
}

public PayloadInjector(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, Utilities utilities) {
  this.service = baseRequestResponse.getHttpService();
  this.base = baseRequestResponse;
  this.insertionPoint = insertionPoint;
  this.utilities      = utilities;
}

public ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe) {
  return this.fuzz(baselineAttack, probe, (String)null);
}

public ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe, String mutation) {
  ArrayList<Attack> attacks = new ArrayList(2);
  Attack breakAttack = this.buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
  if (utilities.identical(baselineAttack, breakAttack)) {
    return new ArrayList();
  } else {
    for(int k = 0; k < probe.getNextEscapeSet().length; ++k) {
      Attack doNotBreakAttack = this.buildAttackFromProbe(probe, probe.getNextEscapeSet()[k], mutation);
      doNotBreakAttack.addAttack(baselineAttack);
      if (!utilities.identical(doNotBreakAttack, breakAttack)) {
        attacks = this.verify(doNotBreakAttack, breakAttack, probe, k, mutation);
        if (!attacks.isEmpty()) {
          break;
        }
      }
    }
    
    return attacks;
  }
}

private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape) {
  return this.verify(doNotBreakAttackSeed, breakAttackSeed, probe, chosen_escape, (String)null);
}

private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape, String mutation) {
  ArrayList<Attack> attacks = new ArrayList(2);
  Attack mergedBreakAttack = new Attack(utilities);
  mergedBreakAttack.addAttack(breakAttackSeed);
  Attack mergedDoNotBreakAttack = new Attack(utilities);
  mergedDoNotBreakAttack.addAttack(doNotBreakAttackSeed);
  Attack tempDoNotBreakAttack = doNotBreakAttackSeed;
  
  for(int i = 0; i < 5; ++i) {
    Attack tempBreakAttack = this.buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
    mergedBreakAttack.addAttack(tempBreakAttack);
    if (utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack) || probe.getRequireConsistentEvidence() && utilities.similar(mergedDoNotBreakAttack, tempBreakAttack)) {
      return new ArrayList();
    }
    
    tempDoNotBreakAttack = this.buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
    mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
    if (utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack) || probe.getRequireConsistentEvidence() && utilities.similar(mergedBreakAttack, tempDoNotBreakAttack)) {
      return new ArrayList();
    }
  }
  
  tempDoNotBreakAttack = this.buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
  mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
  Attack tempBreakAttack = this.buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
  mergedBreakAttack.addAttack(tempBreakAttack);
  if (utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack) || probe.getRequireConsistentEvidence() && utilities.similar(mergedBreakAttack, tempDoNotBreakAttack)) {
    return new ArrayList();
  } else {
    attacks.add(mergedBreakAttack);
    attacks.add(mergedDoNotBreakAttack);
    return attacks;
  }
}

private Attack buildAttackFromProbe(Probe probe, String payload) {
  return this.buildAttackFromProbe(probe, payload, (String)null);
}

private Attack buildAttackFromProbe(Probe probe, String payload, String mutation) {
  boolean randomAnchor = probe.getRandomAnchor();
  byte prefix = probe.getPrefix();
  String anchor = "";
  if (randomAnchor) {
    anchor = utilities.generateCanary();
  }
  
  String base_payload = payload;
  if (prefix == Probe.PREPEND) {
    payload = payload + this.insertionPoint.getBaseValue();
  } else if (prefix == Probe.APPEND) {
    payload = this.insertionPoint.getBaseValue() + anchor + payload;
  } else if (prefix != Probe.REPLACE) {
    utilities.err("Unknown payload position");
  }
  
  IHttpRequestResponse req = this.buildRequest(payload, probe.useCacheBuster(), mutation);
  if (randomAnchor) {
    req = utilities.highlightRequestResponse(req, anchor, anchor, this.insertionPoint);
  }
  
  return new Attack(req, probe, base_payload, anchor, utilities);
}

public IHttpRequestResponse buildRequest(String payload, boolean needCacheBuster) {
  return this.buildRequest(payload, needCacheBuster, (String)null);
}

IHttpRequestResponse buildRequest(String payload, boolean needCacheBuster, String mutation) {
  byte[] request = this.insertionPoint.buildRequest(payload.getBytes());
  if (needCacheBuster) {
    request = utilities.addCacheBuster(request, utilities.generateCanary());
  }
  
  boolean forceHttp1 = false;
  if (mutation != null) {
    forceHttp1 = true;
    HeaderMutator mutator = new HeaderMutator(utilities);
    
    try {
      byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
      request = newRequest;
    } catch (IOException var8) {
      IOException e = var8;
      utilities.out(e.toString());
    }
  }
  
  IHttpRequestResponse requestResponse = utilities.attemptRequest(this.service, request, forceHttp1);
  return requestResponse;
}

public Attack probeAttack(String payload) {
  return this.probeAttack(payload, (String)null);
}

public Attack probeAttack(String payload, String mutation) {
  byte[] request = this.insertionPoint.buildRequest(payload.getBytes());
  request = utilities.addCacheBuster(request, utilities.generateCanary());
  boolean forceHttp1 = false;
  if (mutation != null) {
    forceHttp1 = true;
    HeaderMutator mutator = new HeaderMutator(utilities);
    
    try {
      byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
      request = newRequest;
    } catch (IOException var7) {
    }
  }
  
  IHttpRequestResponse requestResponse = utilities.attemptRequest(this.service, request, forceHttp1);
  return new Attack(requestResponse, (Probe)null, (String)null, "", utilities);
}

Attack buildAttack(String payload, boolean random) {
  String canary = "";
  if (random) {
    canary = utilities.generateCanary();
  }
  
  return new Attack(this.buildRequest(canary + payload, !random), (Probe)null, (String)null, canary, utilities);
}
}
