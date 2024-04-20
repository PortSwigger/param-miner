package burp.model.scanning.mining;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.ParamScan;
import burp.model.scanning.Scan;
import burp.model.utilities.scan.Resp;
import burp.model.utilities.misc.Utilities;

import java.util.List;

public class NormalisedParamScan extends ParamScan {

    public NormalisedParamScan(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String canary = "kkvjq%61mdk";
        byte[] poisonReq = utilities.addCacheBuster(insertionPoint.buildRequest(canary.getBytes()), Utilities.generateCanary());
        byte[] victimReq = Utilities.replaceFirst(poisonReq, "kkvjq%61".getBytes(), "kkvjqa".getBytes());

        IHttpService service = baseRequestResponse.getHttpService();

        Resp resp = Scan.request(service, poisonReq, utilities);
        if (utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            launcher.getTaskEngine().candidates.incrementAndGet();

            for (int i=0; i<5; i++) {
                Scan.request(service, poisonReq, utilities);
            }

            Resp victimResp = Scan.request(service, victimReq, utilities);
            if (utilities.containsBytes(victimResp.getReq().getResponse(), canary.getBytes())) {
                report("URL-decoded parameter", "The application appears to URL-decode parameters before placing them in the cache key, which may enable DoS attacks and also makes other vulnerabilities more exploitable. This was confirmed using the "+insertionPoint.getInsertionPointName()+" parameter. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", utilities, resp, victimResp);
            }
        }

        return null;
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }
}
