package burp;

import java.util.ArrayList;
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

   static boolean dynamicOnly(PayloadInjector headerInjector, String name) {
       String realName = name.split("~")[0];

       Attack softBase = new Attack();
       softBase.addAttack(headerInjector.buildAttack(realName+"~%r", false));
       softBase.addAttack(headerInjector.buildAttack(realName+"~%r", false));
       softBase.addAttack(headerInjector.buildAttack(realName+"~%r", false));

       // ensure the static input is already cached
       headerInjector.buildAttack(realName+"~static", false);
       headerInjector.buildAttack(realName+"~static", false);

       Probe validParam = new Probe("Found unlinked param: " + realName, 4, realName+"~static");
       validParam.setEscapeStrings(realName+"~%r");
       validParam.setRandomAnchor(false);
       validParam.setPrefix(Probe.REPLACE);
       ArrayList<Attack> confirmed = headerInjector.fuzz(softBase, validParam);

       return !confirmed.isEmpty();
   }

    static boolean magicIP(PayloadInjector headerInjector, String name) {
        String realName = name.split("~")[0];
        Attack softBase = new Attack();
        softBase.addAttack(headerInjector.buildAttack(realName+"~52.12.1.1", false));
        softBase.addAttack(headerInjector.buildAttack(realName+"~52.12.1.2", false));
        Probe magicValue = new Probe("Magic param value: 127.0.0.1", 4, realName+"~127.0.0.1");
        magicValue.setEscapeStrings(realName+"~%52.12.1.3");
        magicValue.setRandomAnchor(false);
        magicValue.setPrefix(Probe.REPLACE);
        ArrayList<Attack> confirmed = headerInjector.fuzz(softBase, magicValue);
        //BulkUtilities.callbacks.addScanIssue(BulkUtilities.reportReflectionIssue(evidence.toArray(new Attack[2]), baseRequestResponse, "Magic IP", "Unlinked parameter identified."));
        return !confirmed.isEmpty();
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
        String left = BulkUtilities.generateCanary();
        String right = BulkUtilities.generateCanary();
        Resp resp = Scan.request(baseRequestResponse.getHttpService(), insertionPoint.buildRequest((left+send+right).getBytes()));
        if (BulkUtilities.contains(resp, left+expect+right)) {
            Scan.report("Transformation: "+send+"---"+expect, "", resp);
            return true;
        }
        return false;
    }


}
