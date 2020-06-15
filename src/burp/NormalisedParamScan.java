package burp;

import java.util.List;

public class NormalisedParamScan extends ParamScan {

    NormalisedParamScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String canary = "kkvjq%61mdk";
        byte[] poisonReq = Utilities.addCacheBuster(insertionPoint.buildRequest(canary.getBytes()), Utilities.generateCanary());
        byte[] victimReq = Utilities.replaceFirst(poisonReq, "kkvjq%61".getBytes(), "kkvjqa".getBytes());

        IHttpService service = baseRequestResponse.getHttpService();

        Resp resp = request(service, poisonReq);
        if (Utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            BulkScanLauncher.getTaskEngine().candidates.incrementAndGet();

            for (int i=0; i<5; i++) {
                request(service, poisonReq);
            }

            Resp victimResp = request(service, victimReq);
            if (Utilities.containsBytes(victimResp.getReq().getResponse(), canary.getBytes())) {
                report("Normalised cache key", canary, resp, victimResp);
            }
        }

        return null;
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }
}
