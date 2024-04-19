package burp.model.header;

import java.util.List;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.ParamGuesser;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.Scan;
import burp.model.utilities.Utilities;

public class HeaderPoison extends Scan {

    public HeaderPoison(String name, Utilities utilities, BulkScanLauncher launcher) {
        super(name, utilities, launcher);
        scanSettings.importSettings(BurpExtender.guessSettings);
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, Utilities.PARAM_HEADER, BurpExtender.paramGrabber, null, 2147483647, utilities.globalSettings, utilities).run();
        return null;
    }
}