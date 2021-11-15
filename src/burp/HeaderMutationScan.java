package burp;

import java.util.ArrayList;
import java.util.List;

public class HeaderMutationScan extends Scan {
    HeaderMutationScan(String name) {
        super(name);
    }


    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        //new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, Utilities.globalSettings).run();
        HeaderMutationGuesser guesser = new HeaderMutationGuesser(req, Utilities.globalSettings);
        ArrayList<String> mutations = guesser.guessMutations();
        guesser.reportMutations(mutations);
        return null;
    }
}
