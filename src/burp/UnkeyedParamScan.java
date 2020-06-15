package burp;


import java.util.List;

public class UnkeyedParamScan extends ParamScan {

    UnkeyedParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // don't scan POST
        if (baseRequestResponse.getRequest()[0] == 'P') {
            return null;
        }

        IHttpService service = baseRequestResponse.getHttpService();

        // set value to canary
        String canary = "akzldka";
        String cacheBuster = Utilities.generateCanary();

        byte[] poison = insertionPoint.buildRequest(canary.getBytes());

        poison = Utilities.addCacheBuster(poison, cacheBuster);

        // confirm we have input reflection
        Resp resp = request(service, poison);
        if (!Utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {

            // todo fix this afterwards
//            poison = Utilities.replaceFirst(poison, "/", "//");
//            resp = request(service, poison);
//            if (!Utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
//                return null;
//            }
//            pathBust = true;

            return null;
        }

        // try to apply poison
        for (int i=0; i<5; i++) {
            request(service, poison);
        }

        // see if the poison stuck
        String victimCanary = "zzmkdfq";
        byte[] victim = insertionPoint.buildRequest(victimCanary.getBytes());
        victim = Utilities.addCacheBuster(victim, cacheBuster);
        Resp poisoned = request(service, victim);
        if (!Utilities.containsBytes(poisoned.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        if (Utilities.containsBytes(poisoned.getReq().getResponse(), victimCanary.getBytes())) {
            report("Internal cache poisoning?", "The second response contains elements of the previous request and the victim request: "+canary + " "+victimCanary, resp, poisoned);
        }

        // identify whether the URL-based cachebuster is necessary
        byte[] victim2 = Utilities.replace(victim, cacheBuster, cacheBuster+"2");
        Resp poisonedDueToUnkeyedQuery = request(service, victim2);

        if (Utilities.containsBytes(poisonedDueToUnkeyedQuery.getReq().getResponse(), canary.getBytes())) {
            report("Query string unkeyed/whitelist ", "The second response contains a payload from the previous request: "+canary, resp, poisonedDueToUnkeyedQuery);
        }
        else {
            report("Query param blacklist ", "The second response contains a payload from previous request: "+canary, resp, poisoned);
        }

        return null;
    }
}