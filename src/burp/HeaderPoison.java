package burp;

import java.util.List;

public class HeaderPoison extends Scan {

    HeaderPoison(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, Utilities.globalSettings).run();
        return null;
    }
}