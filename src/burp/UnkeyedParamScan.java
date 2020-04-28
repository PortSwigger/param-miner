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

        // todo flip this back to false afterwards
        boolean pathBust = true;
        poison = Utilities.addCacheBuster(poison, cacheBuster, pathBust);

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

        for (int i=0; i<5; i++) {
            request(service, poison);
        }

        byte[] victim = insertionPoint.buildRequest("foobar".getBytes());

        victim = Utilities.addCacheBuster(victim, cacheBuster, pathBust);

        Resp poisoned = request(service, victim);
        if (!Utilities.containsBytes(poisoned.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        byte[] victim2 = Utilities.replaceFirst(victim, cacheBuster, cacheBuster+"2");
        Resp poisonedDueToUnkeyedQuery = request(service, victim2);


//        if (insertionPoint.getInsertionPointName().equals(Utilities.globalSettings.getString("dummy param name"))) {
//            // if this is a dummy param, it can't be a blacklist
//            // unless.. argh! need a followup
//        }

        if (Utilities.containsBytes(poisonedDueToUnkeyedQuery.getReq().getResponse(), canary.getBytes())) {
            report("Query string unkeyed/whitelist "+pathBust, canary, resp, poisonedDueToUnkeyedQuery);
        }
        else {
            report("Query param blacklist "+pathBust, canary, resp, poisoned);
        }

        return null;
    }
}