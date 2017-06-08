package burp;

import java.util.ArrayList;


class PayloadInjector {

    private IHttpRequestResponse baseRequestResponse;
    private IScannerInsertionPoint insertionPoint;

    PayloadInjector(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        this.baseRequestResponse = baseRequestResponse;
        this.insertionPoint = insertionPoint;
    }

    // fixme horribly inefficient
    ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack = buildAttackFromProbe(probe, probe.getNextBreak());

        if (Utilities.identical(baselineAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for(int k=0; k<probe.getNextEscapeSet().length; k++) {
            Attack doNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k]);
            doNotBreakAttack.addAttack(baselineAttack);
            if(!Utilities.identical(doNotBreakAttack, breakAttack)) {
                attacks = verify(doNotBreakAttack, breakAttack, probe, k);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }

        return attacks;
    }

    private ArrayList<Attack> verify(Attack doNotBreakAttackSeed, Attack breakAttackSeed, Probe probe, int chosen_escape) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack mergedBreakAttack = new Attack();
        mergedBreakAttack.addAttack(breakAttackSeed);
        Attack mergedDoNotBreakAttack = new Attack();
        mergedDoNotBreakAttack.addAttack(doNotBreakAttackSeed);

        Attack tempDoNotBreakAttack = doNotBreakAttackSeed;

        for(int i=0; i<Utilities.CONFIRMATIONS; i++) {
            Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
            mergedBreakAttack.addAttack(tempBreakAttack);

            if(Utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                    || (probe.getRequireConsistentEvidence() && Utilities.similar(mergedDoNotBreakAttack, tempBreakAttack))) {
                return new ArrayList<>();
            }

            tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]);
            mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);

            if(Utilities.similarIsh(mergedDoNotBreakAttack, mergedBreakAttack, tempDoNotBreakAttack, tempBreakAttack)
                    || (probe.getRequireConsistentEvidence() && Utilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
                return new ArrayList<>();
            }

        }

        // this final probe pair is sent out of order, to prevent alternation false positives
        tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]);
        mergedDoNotBreakAttack.addAttack(tempDoNotBreakAttack);
        Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
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


    private Attack buildAttackFromProbe(Probe probe, String payload) {
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


        IHttpRequestResponse req = buildRequest(payload, probe.useCacheBuster());
        if(randomAnchor) {
            req = Utilities.highlightRequestResponse(req, anchor, anchor, insertionPoint);
        }

        return new Attack(req, probe, base_payload, anchor);
    }

    IHttpRequestResponse buildRequest(String payload, boolean needCacheBuster) {

        byte[] request = insertionPoint.buildRequest(payload.getBytes());

        if (needCacheBuster) {
            IParameter cacheBuster = burp.Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
            request = burp.Utilities.helpers.addParameter(request, cacheBuster);
        }

        IHttpRequestResponse requestResponse = burp.Utilities.attemptRequest(baseRequestResponse.getHttpService(), request);

        return requestResponse;// Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)
    }


    Attack buildAttack(String payload, boolean random) {
        String canary = "";
        if (random) {
            canary = Utilities.generateCanary();
        }

        return new Attack(buildRequest(canary+payload, !random), null, null, canary);

    }

}
