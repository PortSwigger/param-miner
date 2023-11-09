package burp;

import java.util.List;

class HeaderGuessScan extends Scan {

    HeaderGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, BulkUtilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        return null;
    }
}

class URLGuessScan extends Scan {

    URLGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, IParameter.PARAM_URL, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        return null;
    }
}

class CookieGuessScan extends Scan {

    CookieGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, IParameter.PARAM_COOKIE, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        return null;
    }
}