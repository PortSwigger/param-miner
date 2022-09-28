package burp;

import java.util.List;

public class UnexpectedDecodeScan extends ParamScan
{
    public UnexpectedDecodeScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_HEADER) {
            return null;
        }
        String left = Utilities.generateCanary();
        String right = Utilities.generateCanary();
        Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest((left+"%61"+right).getBytes()));
        if (Utilities.contains(resp, left+"a"+right)) {
            report("Header URL-decode", "", resp);
        }
        return null;
    }
}
