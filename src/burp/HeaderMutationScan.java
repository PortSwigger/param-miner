package burp;

import java.util.ArrayList;
import java.util.List;

public class HeaderMutationScan extends Scan {
    HeaderMutationScan(String name) {
        super(name);
    }


    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        //new ParamGuesser(req, false, BulkUtilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        HeaderMutationGuesser guesser = new HeaderMutationGuesser(req, BulkUtilities.globalSettings);
        ArrayList<String> mutations = guesser.guessMutations();
        guesser.reportMutations(mutations);
        return null;
    }
}
