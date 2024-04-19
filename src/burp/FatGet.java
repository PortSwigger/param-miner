package burp;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.ParamScan;
import burp.albinowaxUtils.Resp;
import burp.model.utilities.Utilities;

import java.util.List;

public class FatGet extends ParamScan {

    FatGet(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // don't scan POST
        if (baseRequestResponse.getRequest()[0] == 'P') {
            return null;
        }

        // set value to canary
        String canary = utilities.generateCanary();

        String fullValue = insertionPoint.getBaseValue()+canary;
        byte[] poison = insertionPoint.buildRequest(fullValue.getBytes());

        // convert to POST
        poison = utilities.helpers.toggleRequestMethod(poison);

        poison = Utilities.fixContentLength(Utilities.replaceFirst(poison, canary.getBytes(), (canary).getBytes()));

        // convert method back to GET
        poison = utilities.setMethod(poison, "GET");

        poison = utilities.addOrReplaceHeader(poison, "X-HTTP-Method-Override", "POST");
        poison = utilities.addOrReplaceHeader(poison, "X-HTTP-Method", "POST");
        poison = utilities.addOrReplaceHeader(poison, "X-Method-Override", "POST");

        poison = utilities.addCacheBuster(poison, Utilities.generateCanary());

        IHttpService service = baseRequestResponse.getHttpService();

        Resp   resp     = request(service, poison, utilities);
        byte[] response = resp.getReq().getResponse();

        if (utilities.containsBytes(response, canary.getBytes())) {

            recordCandidateFound();

            // report("Fat-GET body reflection", canary, resp);
            for (int i=0; i<5; i++) {
                request(service, poison, utilities);
            }

            //String toReplace = insertionPoint.getInsertionPointName()+"="+fullValue;
            String toReplace = canary;

            byte[] getPoison = utilities.fixContentLength(utilities.replaceFirst(poison, toReplace.getBytes(), "".getBytes()));
//            byte[] getPoison = baseRequestResponse.getRequest();
//            getPoison = utilities.appendToQuery(getPoison, "x="+cacheBuster);


            Resp poisonedResp = request(service, getPoison, utilities);
            if (utilities.containsBytes(poisonedResp.getReq().getResponse(), canary.getBytes())) {
                report("Web Cache Poisoning via Fat GET", "The application lets users pass parameters in the body of GET requests, but does not include them in the cache key. This was confirmed by injecting the value "+canary+" using the "+insertionPoint.getInsertionPointName()+" parameter, then replaying the request without the injected value, and confirming it still appears in the response.<br><br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", utilities, resp, poisonedResp);
            }
        }

        return null;
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }

}
