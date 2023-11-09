package burp;

import java.util.List;

public class NormalisedPathScan extends Scan {

    NormalisedPathScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = BulkUtilities.appendToQuery(baseReq, "cb="+BulkUtilities.generateCanary());

        Resp base = request(service, BulkUtilities.appendToQuery(baseReq, "cbx=zxcv"));
        short baseCode = base.getStatus();

        byte[] poisonReq = BulkUtilities.replaceFirst(baseReq, "?".getBytes(), "%3f".getBytes());

        Resp resp = request(service, poisonReq);
        short poisonedCode = resp.getStatus();

        if (baseCode != poisonedCode) {
            BulkScanLauncher.getTaskEngine().candidates.incrementAndGet();

            for (int i=0; i<5; i++) {
                request(service, poisonReq);
            }

            Resp victimResp = request(service, baseReq);
            short victimCode = victimResp.getStatus();

            if (victimCode == poisonedCode) {
                report("Web Cache Poisoning: URL-decoded path", "The application appears to URL-decode the path before placing it in the cache key, which may enable DoS attacks and also makes other vulnerabilities more exploitable. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", base, resp, victimResp);
            }
        }


        return null;
    }
}
