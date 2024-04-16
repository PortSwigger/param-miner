package burp;

import java.util.List;

import burp.albinowaxUtils.BulkScanLauncher;
import burp.albinowaxUtils.Resp;
import burp.albinowaxUtils.Scan;
import burp.albinowaxUtils.Utilities;

public class NormalisedPathScan extends Scan {

    NormalisedPathScan(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = Utilities.appendToQuery(baseReq, "cb="+utilities.generateCanary());

        Resp  base     = request(service, Utilities.appendToQuery(baseReq, "cbx=zxcv"), utilities);
        short baseCode = base.getStatus();

        byte[] poisonReq = Utilities.replaceFirst(baseReq, "?".getBytes(), "%3f".getBytes());

        Resp resp = request(service, poisonReq, utilities);
        short poisonedCode = resp.getStatus();

        if (baseCode != poisonedCode) {
            launcher.getTaskEngine().candidates.incrementAndGet();

            for (int i=0; i<5; i++) {
                request(service, poisonReq, utilities);
            }

            Resp victimResp = request(service, baseReq, utilities);
            short victimCode = victimResp.getStatus();

            if (victimCode == poisonedCode) {
                report("Web Cache Poisoning: URL-decoded path", "The application appears to URL-decode the path before placing it in the cache key, which may enable DoS attacks and also makes other vulnerabilities more exploitable. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", utilities, base, resp, victimResp);
            }
        }


        return null;
    }
}
