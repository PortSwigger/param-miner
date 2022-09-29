package burp;

import java.util.List;

public class PingbackScan extends ParamScan
{
    public PingbackScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String collab = BasicCollab.getPayload();
        Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(collab.getBytes()));
        if (BasicCollab.checkPayload(collab.split("[.]")[0])) {
            report("ping", "", resp);
        }
        return null;
    }
}
