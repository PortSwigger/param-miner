package burp;

import java.util.List;

public class NormalisedPathScan extends Scan {

    NormalisedPathScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = Utilities.appendToQuery(baseReq, "cb="+Utilities.generateCanary());

        Resp base = request(service, Utilities.appendToQuery(baseReq, "cbx=zxcv"));
        short baseCode = base.getStatus();

        byte[] poisonReq = Utilities.replaceFirst(baseReq, "?".getBytes(), "%3f".getBytes());

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
                report("Normalised cache key: ?", baseCode+":"+victimCode, base, resp, victimResp);
            }
        }


        return null;
    }
}
