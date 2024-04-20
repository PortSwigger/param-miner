package burp.model.scanning.mining;

import java.util.List;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.model.scanning.guessing.param.ParamGrabber;
import burp.model.scanning.guessing.param.ParamGuesser;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.Scan;
import burp.model.utilities.misc.Utilities;
import burp.view.SettingsBox;

public class HeaderPoison extends Scan {

    public HeaderPoison(String name, Utilities utilities, BulkScanLauncher launcher, SettingsBox guessSettings, ParamGrabber paramGrabber) {
        super(name, utilities, launcher);
        scanSettings.importSettings(guessSettings);
        this.paramGrabber = paramGrabber;
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse req) {
        new ParamGuesser(req, false, Utilities.PARAM_HEADER, paramGrabber, null, 2147483647, utilities.globalSettings, utilities).run();
        return null;
    }

private final ParamGrabber paramGrabber;
}