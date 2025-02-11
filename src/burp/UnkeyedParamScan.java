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
        String cacheBuster = BulkUtilities.generateCanary();

        byte[] poison = insertionPoint.buildRequest(canary.getBytes());

        poison = BulkUtilities.addCacheBuster(poison, cacheBuster);

        // confirm we have input reflection
        Resp resp = request(service, poison);
        if (!BulkUtilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            // todo try path-busting
            return null;
        }

        // try to apply poison
        for (int i=0; i<5; i++) {
            request(service, poison);
        }

        // see if the poison stuck
        String victimCanary = "zzmkdfq";
        byte[] victim = insertionPoint.buildRequest(victimCanary.getBytes());
        victim = BulkUtilities.addCacheBuster(victim, cacheBuster);
        Resp poisoned = request(service, victim);
        if (!BulkUtilities.containsBytes(poisoned.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        if (BulkUtilities.containsBytes(poisoned.getReq().getResponse(), victimCanary.getBytes())) {
            report("Internal cache poisoning?", "The second response contains elements of the previous request and the victim request, suggesting it may be vulnerable to internal cache poisoning. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", resp, poisoned);
        }

        // identify whether the URL-based cachebuster is necessary
        byte[] victim2 = BulkUtilities.replace(victim, cacheBuster, cacheBuster+"2");
        Resp poisonedDueToUnkeyedQuery = request(service, victim2);

        if (BulkUtilities.containsBytes(poisonedDueToUnkeyedQuery.getReq().getResponse(), canary.getBytes())) {
            report("Web Cache Poisoning: Query string unkeyed?", "The application does not include the query string in the cache key. This was confirmed by injecting the value '"+canary+"' using the "+insertionPoint.getInsertionPointName()+" parameter, then replaying the request without the injected value, and confirming it still appears in the response. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", resp, poisonedDueToUnkeyedQuery);
        }
        else {
            report("Web Cache Poisoning: Query param blacklist ", "The application excludes certain parameters from the cache key. This was confirmed by injecting the value '"+canary+"' using the "+insertionPoint.getInsertionPointName()+" parameter, then replaying the request without the injected value, and confirming it still appears in the response. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", resp, poisoned);
        }

        return null;
    }
}