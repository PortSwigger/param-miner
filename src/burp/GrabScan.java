package burp;

import burp.albinowaxUtils.Utilities;

import java.util.ArrayList;
import java.util.List;

public class GrabScan implements IScannerCheck {

    private ParamGrabber paramGrabber;

    GrabScan(ParamGrabber paramGrabber, Utilities utilites) {
        this.paramGrabber = paramGrabber;
        this.utilites     = utilites;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (utilites.globalSettings.getBoolean("learn observed words")) {
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

private final Utilities utilites;
}
