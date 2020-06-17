package burp;

import java.util.List;

public class PortDOS extends Scan {

    PortDOS(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = Utilities.addCacheBuster(baseReq, Utilities.generateCanary());

        String canary = "41810";
        byte[] poisonReq = Utilities.addOrReplaceHeader(baseReq, "Host", service.getHost()+":"+canary);

        if (Utilities.containsBytes(baseReq, canary.getBytes())) {
            return null;
        }


        Resp resp = request(service, poisonReq);
        if (Utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            recordCandidateFound();

            for (int i=0; i<5; i++) {
                request(service, poisonReq);
            }

            Resp victimResp = request(service, baseReq);
            if (Utilities.containsBytes(victimResp.getReq().getResponse(), canary.getBytes())) {
                report("Port-DOS", canary, resp, victimResp);
            }
        }


        return null;
    }
}
