package burp.model.scanning;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.model.scanning.guessing.param.ParamGrabber;
import burp.model.utilities.misc.Utilities;

import java.util.ArrayList;
import java.util.List;

public class GrabScan implements IScannerCheck {

    private final ParamGrabber paramGrabber;

    public GrabScan(ParamGrabber paramGrabber, Utilities utilities) {
      this.paramGrabber = paramGrabber;
      this.utilities    = utilities;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (utilities.globalSettings.getBoolean("learn observed words")) {
            paramGrabber.saveParams(baseRequestResponse);
        }
        return new ArrayList<>();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }

    private final Utilities utilities;
}
