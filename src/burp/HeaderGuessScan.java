package burp;

import java.util.List;

public class HeaderGuessScan extends Scan {

    HeaderGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, Utilities.globalSettings).run();
        return null;
    }
}