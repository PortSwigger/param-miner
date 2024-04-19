package burp;

import java.util.List;

import burp.albinowaxUtils.BulkScanLauncher;
import burp.albinowaxUtils.Scan;

public class HeaderPoison extends Scan {

    HeaderPoison(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, utilities.globalSettings, utilities).run();
        return null;
    }
}