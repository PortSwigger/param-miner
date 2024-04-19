package burp.model.scanning;

import java.util.List;

import burp.IHttpService;
import burp.IScanIssue;
import burp.albinowaxUtils.Resp;
import burp.model.utilities.Utilities;

public class PortDosScan extends Scan {

    public PortDosScan(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = utilities.addCacheBuster(baseReq, utilities.generateCanary());

        String canary = "41810";
        byte[] poisonReq = utilities.addOrReplaceHeader(baseReq, "Host", service.getHost()+":"+canary);

        if (utilities.containsBytes(baseReq, canary.getBytes())) {
            return null;
        }


        Resp resp = request(service, poisonReq, utilities);
        if (utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            recordCandidateFound();

            for (int i=0; i<5; i++) {
                request(service, poisonReq, utilities);
            }

            Resp victimResp = request(service, baseReq, utilities);
            if (utilities.containsBytes(victimResp.getReq().getResponse(), canary.getBytes())) {
                report("Web Cache Poisoning: unkeyed port", "The application does not include the port in the host header in the cache key. This may enable a single-request DoS attack. More serious attacks may be possible depending on how much validation is applied to the port. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", utilities, resp, victimResp);
            }
        }


        return null;
    }
}
