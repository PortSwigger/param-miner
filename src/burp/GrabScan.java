package burp;

import java.util.ArrayList;
import java.util.List;

public class GrabScan implements IScannerCheck {

    private ParamGrabber paramGrabber;

    GrabScan(ParamGrabber paramGrabber) {
        this.paramGrabber = paramGrabber;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (Utilities.globalSettings.getBoolean("learn observed words")) {
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
}
