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
        return transformation(baseRequestResponse, insertionPoint, "%61", "a");
    }

    static boolean eatsBackslash(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return transformation(baseRequestResponse, insertionPoint, "\\\\", "\\");
    }

    static boolean utf8(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return transformation(baseRequestResponse, insertionPoint, "\u2424", "\n");
    }

    static boolean utf82(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return transformation(baseRequestResponse, insertionPoint, "\u2424", "\u0024");
    }

    private static boolean transformation(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String send, String expect) {
        String left = Utilities.generateCanary();
        String right = Utilities.generateCanary();
        Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest((left+send+right).getBytes()));
        if (Utilities.contains(resp, left+expect+right)) {
            Scan.report("Transformation: "+send+"---"+expect, "", resp);
            return true;
        }
        return false;
    }


}
