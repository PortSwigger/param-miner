package burp;


import java.util.List;

public class RailsUtmScan extends ParamScan {

    RailsUtmScan(String name) {
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


        byte[] poison = insertionPoint.buildRequest((insertionPoint.getBaseValue()+"&utm_content=x;"+insertionPoint.getInsertionPointName()+"="+canary).getBytes());

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
        byte[] victim = insertionPoint.buildRequest(insertionPoint.getBaseValue().getBytes());
        victim = BulkUtilities.addCacheBuster(victim, cacheBuster);
        Resp poisoned = request(service, victim);
        if (!BulkUtilities.containsBytes(poisoned.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        report("Web Cache Poisoning: Parameter Cloaking", "The application can be manipulated into excluding the "+insertionPoint.getInsertionPointName()+" parameter from the cache key, by disguising it as utm_content. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", resp, poisoned);


        return null;
    }
}