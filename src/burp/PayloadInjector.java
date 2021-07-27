package burp;

import org.graalvm.compiler.core.common.util.Util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;


class PayloadInjector {

    public IHttpService getService() {
        return service;
    }

    private IHttpService service;

    public IScannerInsertionPoint getInsertionPoint() {
        return insertionPoint;
    }

    private IScannerInsertionPoint insertionPoint;

    public IHttpRequestResponse getBase() {
        return base;
    }

    private IHttpRequestResponse base;

    PayloadInjector(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        this.service = baseRequestResponse.getHttpService();
        this.base = baseRequestResponse;
        this.insertionPoint = insertionPoint;
    }

    // fixme horribly inefficient
    ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe) {
        return fuzz(baselineAttack, probe, null);
    }

    ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe, String mutation) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);

        if (Utilities.identical(baselineAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for(int k=0; k<probe.getNextEscapeSet().length; k++) {
            Attack doNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k], mutation);
            doNotBreakAttack.addAttack(baselineAttack);
            if(!Utilities.identical(doNotBreakAttack, breakAttack)) {
                attacks = verify(doNotBreakAttack, breakAttack, probe, k, mutation);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }

        return attacks;
    }

    private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape, String mutation) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack mergedBreakAttack = new Attack();
        mergedBreakAttack.addAttack(breakAttackSeed);
        Attack mergedDoNotBreakAttack = new Attack();
        mergedDoNotBreakAttack.addAttack(doNotBreakAttackSeed);

        Attack tempDoNotBreakAttack = doNotBreakAttackSeed;

        for(int i=0; i<Utilities.CONFIRMATIONS; i++) {
            Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
            mergedBreakAttack.addAttack(tempBreakAttack);

            if(Utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                    || (probe.getRequireConsistentEvidence() && Utilities.similar(mergedDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
            mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);

            if(Utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                    || (probe.getRequireConsistentEvidence() && Utilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
                return new ArrayList<>();
            }

        }

        // this final probe pair is sent out of order, to prevent alternation false positives
        tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape], mutation);
        mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
        Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak(), mutation);
        mergedBreakAttack.addAttack(tempBreakAttack);

        // point is to exploit response attributes that vary in "don't break" responses (but are static in 'break' responses)
        if(Utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                || (probe.getRequireConsistentEvidence() && Utilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
            return new ArrayList<>();
        }

        attacks.add(mergedBreakAttack);
        attacks.add(mergedDoNotBreakAttack);

        return attacks;
    }


    private Attack buildAttackFromProbe(Probe probe, String payload, String mutation) {
        boolean randomAnchor = probe.getRandomAnchor();
        byte prefix = probe.getPrefix();

        String anchor = "";
        if (randomAnchor) {
            anchor = Utilities.generateCanary();
        }
        //else {
        //    payload = payload.replace("z", Utilities.generateCanary());
        //}

        String base_payload = payload;
        if (prefix == Probe.PREPEND) {
            payload += insertionPoint.getBaseValue();
        }
        else if (prefix == Probe.APPEND) {
            payload = insertionPoint.getBaseValue() + anchor + payload;
        }
        else if (prefix == Probe.REPLACE) {
            // payload = payload;
        }
        else {
            Utilities.err("Unknown payload position");
        }


        IHttpRequestResponse req = buildRequest(payload, probe.useCacheBuster(), mutation);
        if(randomAnchor) {
            req = Utilities.highlightRequestResponse(req, anchor, anchor, insertionPoint);
        }

        return new Attack(req, probe, base_payload, anchor);
    }

    IHttpRequestResponse buildRequest(String payload, boolean needCacheBuster) {
        return buildRequest(payload, needCacheBuster, null);
    }

    IHttpRequestResponse buildRequest(String payload, boolean needCacheBuster, String mutation) {

        byte[] request = insertionPoint.buildRequest(payload.getBytes());

        if (needCacheBuster) {
            request = Utilities.addCacheBuster(request, Utilities.generateCanary());
        }

        if (mutation != null) {
            HeaderMutator mutator = new HeaderMutator();
            try {
                byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
                request = newRequest;
            } catch (IOException e) {
                Utilities.out(e.toString());
            }
        }

        IHttpRequestResponse requestResponse = burp.Utilities.attemptRequest(service, request);
        //Utilities.out("Payload: "+payload+"|"+baseRequestResponse.getHttpService().getHost());

        return requestResponse;// Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)
    }

    Attack probeAttack(String payload) {
        return probeAttack(payload, null);
    }

    Attack probeAttack(String payload, String mutation) {
        byte[] request = insertionPoint.buildRequest(payload.getBytes());

        //IParameter cacheBuster = burp.Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
        //request = burp.Utilities.helpers.addParameter(request, cacheBuster);
        //request = burp.Utilities.appendToQuery(request, Utilities.generateCanary()+"=1");
        request = Utilities.addCacheBuster(request, Utilities.generateCanary());

        if (mutation != null) {
            HeaderMutator mutator = new HeaderMutator();
            try {
                byte[] newRequest = mutator.mutateRequest(request, mutation, payload.split("\\|"));
                request = newRequest;
            } catch (java.io.IOException e) {
                //Utilities.out("ERROR: failed to mutate request: " + e.toString());
            }
        }

        IHttpRequestResponse requestResponse = burp.Utilities.attemptRequest(service, request);
        return new Attack(requestResponse, null, null, "");
    }


    Attack buildAttack(String payload, boolean random) {
        String canary = "";
        if (random) {
            canary = Utilities.generateCanary();
        }

        return new Attack(buildRequest(canary+payload, !random, null), null, null, canary);

    }

}
