package burp;

import java.util.ArrayList;
import java.util.List;

import burp.albinowaxUtils.BulkScanLauncher;
import burp.albinowaxUtils.Scan;
import burp.albinowaxUtils.Utilities;

public class HeaderMutationScan extends Scan {
    HeaderMutationScan(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
    }


    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse req) {
        //new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, Utilities.globalSettings).run();
        HeaderMutationGuesser guesser = new HeaderMutationGuesser(req, utilities.globalSettings, utilities);
        ArrayList<String> mutations = guesser.guessMutations();
        guesser.reportMutations(mutations);
        return null;
    }
}
