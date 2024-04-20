package burp.model.scanning.mining;


import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.ParamScan;
import burp.model.utilities.Resp;
import burp.model.utilities.Utilities;

import java.util.List;

public class RailsUtmScan extends ParamScan {

    public RailsUtmScan(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }

    @Override
    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // don't scan POST
        if (baseRequestResponse.getRequest()[0] == 'P') {
            return null;
        }

        IHttpService service = baseRequestResponse.getHttpService();

        // set value to canary
        String canary = "akzldka";
        String cacheBuster = utilities.generateCanary();


        byte[] poison = insertionPoint.buildRequest((insertionPoint.getBaseValue()+"&utm_content=x;"+insertionPoint.getInsertionPointName()+"="+canary).getBytes());

        poison = utilities.addCacheBuster(poison, cacheBuster);

        // confirm we have input reflection
        Resp resp = request(service, poison, utilities);
        if (!utilities.containsBytes(resp.getReq().getResponse(), canary.getBytes())) {
            // todo try path-busting
            return null;
        }

        // try to apply poison
        for (int i=0; i<5; i++) {
            request(service, poison, utilities);
        }

        // see if the poison stuck
        byte[] victim = insertionPoint.buildRequest(insertionPoint.getBaseValue().getBytes());
        victim = utilities.addCacheBuster(victim, cacheBuster);
        Resp poisoned = request(service, victim, utilities);
        if (!utilities.containsBytes(poisoned.getReq().getResponse(), canary.getBytes())) {
            return null;
        }

        report("Web Cache Poisoning: Parameter Cloaking", "The application can be manipulated into excluding the "+insertionPoint.getInsertionPointName()+" parameter from the cache key, by disguising it as utm_content. <br>For further information on this technique, please refer to https://portswigger.net/research/web-cache-entanglement", utilities, resp, poisoned);


        return null;
    }
}