package burp;

import java.util.ArrayList;


class PayloadInjector {

    private IHttpRequestResponse baseRequestResponse;
    private IScannerInsertionPoint insertionPoint;

    PayloadInjector(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        this.baseRequestResponse = baseRequestResponse;
        this.insertionPoint = insertionPoint;
    }

    ArrayList<Attack> fuzz(Attack basicAttack, Probe probe) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack breakAttack;
        Attack doNotBreakAttack;
        breakAttack = buildAttackFromProbe(probe, probe.getNextBreak());

        if (Utilities.identical(basicAttack, breakAttack)) {
            return new ArrayList<>();
        }

        for(int k=0; k<probe.getNextEscapeSet().length; k++) {
            doNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k]);
            doNotBreakAttack.addAttack(basicAttack);
            if(!Utilities.verySimilar(doNotBreakAttack, breakAttack)) {
                attacks = verify(doNotBreakAttack, probe, k);
                if (!attacks.isEmpty()) {
                    break;
                }
            }
        }

        return attacks;
    }

    private ArrayList<Attack> verify(Attack doNotBreakAttack2, Probe probe, int chosen_escape) {
        ArrayList<Attack> attacks = new ArrayList<>(2);
        Attack mergedBreakAttack = null;
        Attack breakAttack;
        Attack doNotBreakAttack = null;

        for(int i=0; i<Utilities.CONFIRMATIONS; i++) {
            breakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
            if(i==0) {
                mergedBreakAttack = breakAttack;
            }
            else {
                mergedBreakAttack.addAttack(breakAttack);
            }

            if(doNotBreakAttack != null && Utilities.verySimilar(doNotBreakAttack, mergedBreakAttack)) {
                return new ArrayList<>();
            }

            Attack tempDoNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]);
            if(i==0) {
                doNotBreakAttack = tempDoNotBreakAttack;
            }
            else {
                doNotBreakAttack.addAttack(tempDoNotBreakAttack);
            }

            if(Utilities.verySimilar(doNotBreakAttack, mergedBreakAttack)) {
                return new ArrayList<>();
            }
        }

        // this final probe pair is sent out of order, to prevent alternation false positives
        doNotBreakAttack.addAttack(buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]));
        breakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
        mergedBreakAttack.addAttack(breakAttack);

        // todo compare mergedBreakAttack instead here? will this actually increase coverage? probably.
        // point is to exploit response attributes that vary in "don't break" responses (but are static in 'break' responses)
        // I'll need to use similar w/mergedbreak attack in the loop too
        if(Utilities.verySimilar(doNotBreakAttack, mergedBreakAttack)) {
            return new ArrayList<>();
        }

        attacks.add(mergedBreakAttack);
        attacks.add(doNotBreakAttack);

        return attacks;
    }


    private Attack buildAttackFromProbe(Probe probe, String payload) {
        boolean randomAnchor = probe.getRandomAnchor();
        byte prefix = probe.getPrefix();

        String anchor = "";
        if (randomAnchor) {
            anchor = Utilities.generateCanary();
        }

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


        IHttpRequestResponse req = buildRequest(payload);
        if(randomAnchor) {
            req = Utilities.highlightRequestResponse(req, anchor, anchor, insertionPoint);
        }

        return new Attack(req, probe, base_payload, anchor);
    }

    IHttpRequestResponse buildRequest(String payload) {
        byte[] request = insertionPoint.buildRequest(payload.getBytes());
        IParameter cacheBuster = burp.Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
        request = burp.Utilities.helpers.addParameter(request, cacheBuster);

        return burp.Utilities.callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), request); // Utilities.buildRequest(baseRequestResponse, insertionPoint, payload)
    }


    Attack buildAttack(String payload, boolean random) {
        String canary = "";
        if (random) {
            canary = Utilities.generateCanary();
        }

        return new Attack(buildRequest(canary+payload), null, null, canary);

    }

}
