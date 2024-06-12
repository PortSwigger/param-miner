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

class BodyGuessScan extends Scan {

    BodyGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    List<IScanIssue> doScan(IHttpRequestResponse req) {
        IRequestInfo info = BulkUtilities.helpers.analyzeRequest(req);
        List<IParameter> params = info.getParameters();
        for (IParameter param: params) {
            byte type = param.getType();
            if (type == IParameter.PARAM_URL || type == IParameter.PARAM_COOKIE) {
                continue;
            }
            new ParamGuesser(req, false, type, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
            return null;
        }
        new ParamGuesser(req, false, IParameter.PARAM_BODY, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
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


class EverythingGuessScan extends Scan {
    EverythingGuessScan(String name) {
        super(name);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, IParameter.PARAM_URL, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        new ParamGuesser(req, false, BulkUtilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        new ParamGuesser(req, false, IParameter.PARAM_COOKIE, BurpExtender.paramGrabber, null, 2147483647, BulkUtilities.globalSettings).run();
        return null;
    }
}
