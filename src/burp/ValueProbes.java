package burp;

import java.util.List;

public class ValueProbes
{
   static boolean triggersPingback(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
       String collab = BasicCollab.getPayload();
       Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(collab.getBytes()));
       if (BasicCollab.checkPayload(collab.split("[.]")[0])) {
           // report("ping", "", resp);
           return true;
       }
       return false;
   }

    static boolean urlDecodes(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
//        if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_HEADER) {
//            return null;
//        }
        String left = Utilities.generateCanary();
        String right = Utilities.generateCanary();
        Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest((left+"%61"+right).getBytes()));
        if (Utilities.contains(resp, left+"a"+right)) {
            Scan.report("Header URL-decode", "", resp);
            return true;
        }
        return false;
    }


}
