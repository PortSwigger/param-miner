package burp;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static burp.Lenscrack.reportPairs;

public class TimeInjector extends ParamScan {
    TimeInjector(String name) {
        super(name);
        scanSettings.register("use turbo", false, "Use turbo engine in RespPair");
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {

        AttackPairFactory attacks = new AttackPairFactory(baseRequestResponse, iScannerInsertionPoint);
        String baseValue = iScannerInsertionPoint.getBaseValue();
        String canary = "$canary";


        // todo scan path-params for double URL encoding?

        attacks.creatAttackPair("Rest", baseValue+"%23"+canary, baseValue+"%21"+canary);
        //attacks.creatAttackPair("EL-RCE", baseValue+"${\"x\"}", baseValue+"${\"x\"\"}");
        //attacks.creatAttackPair("URL-v3", baseValue+"#"+canary, baseValue+"$"+canary);
        attacks.creatAttackPair("Escape-sequence-cb", canary+"\\u0061", canary+"\\v0061");
        attacks.creatAttackPair("Double-quote", canary+"x\"\\yz", canary+"x\\\"z");
        attacks.creatAttackPair("Single-quote", canary+"x'\\z", canary+"x\\'z");
        attacks.creatAttackPair("SQL-apos", canary+"x''z", canary+"x'z'z");
//
//
        attacks.creatAttackPair("XML Entity-cb", canary+"&amp;", canary+"&amx;");
        //attacks.creatAttackPair("XML quote", "x\" y='", "x'\" y=\"");
        //attacks.creatAttackPair("SQL LIKE", "a%", "Z%");
        //attacks.creatAttackPair("SQL LIKEDUD", "!", "[!]");
        //attacks.creatAttackPair("Traversal", "./."+baseValue, "./"+baseValue);
//        if (StringUtils.isNumeric(baseValue)) {
//            //attacks.creatAttackPair("Divide", baseValue+"/1", baseValue+"/0");
//            attacks.creatAttackPair("Abs", "abs("+baseValue+")", "abq("+baseValue+")");
//        } else {
//
//            //attacks.creatAttackPair("XML quote", "x\"%20y='", "x'\"%20y=\"");
//            // attacks.creatAttackPair("Traversal", "./../"+baseValue, "././"+baseValue);
//
////            attacks.creatAttackPair("Double-quote", "x\"\\yz", "x\\\"z");
////            attacks.creatAttackPair("Single-quote", "x'\\z", "x\\'z");
////            if (attacks.pairs.get("Double-quote").valid()) {
////                if (attacks.pairs.get("Single-quote").valid()) {
////                    return null; // WAF'd
////                }
////                attacks.creatAttackPair("JSON", "x\",\"x\":\"", "x\",\":x\"");
////            }
////
////
////            attacks.creatAttackPair("HTML", "<!%20--x", "<!--%20x");
//        }


        ArrayList<RespPair> validPairs = new ArrayList<>();
        ArrayList<RespPair> statusPairs = new ArrayList<>();
        String title = "";
        for (AttackPair pair: attacks.pairs.values()) {
            if (pair.isWAFFP) {
                continue;
            }

            if (pair.valid()) {
                validPairs.add(pair.result);
                title = pair.getTitle();
            } else if (pair.result.codeDiff) {
                statusPairs.add(pair.result);
                title = pair.getTitle();
            }
        }

        if (!validPairs.isEmpty()) {
            reportPairs("Time: "+title, "", "", baseRequestResponse.getRequest(), validPairs.toArray(new RespPair[0]));
        }
        if (!statusPairs.isEmpty()) {
            reportPairs("Status: "+title, "", "", baseRequestResponse.getRequest(), statusPairs.toArray(new RespPair[0]));
        }

        return null;
    }
}


class AttackPairFactory {
    HashMap<String, AttackPair> pairs;
    IHttpRequestResponse baseRequestResponse;

    public AttackPairFactory(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        this.baseRequestResponse = baseRequestResponse;
        this.iScannerInsertionPoint = iScannerInsertionPoint;
        pairs = new HashMap<>();
    }
    IScannerInsertionPoint iScannerInsertionPoint;

    AttackPair creatAttackPair(String title, String left, String right) {
        AttackPair pair = new AttackPair(title, left, right, true);
        pairs.put(title, pair);
        pair.attempt(baseRequestResponse, iScannerInsertionPoint);
        return pair;
    }
}

class AttackPair {
    private String left;
    private String right;
    private String title;

    private boolean antiWAF = false;
    boolean isWAFFP = false;

    public RespPair result;

    public AttackPair(String title, String left, String right) {
        this.left = left;
        this.right = right;
        this.title = title;
    }

    public AttackPair(String title, String left, String right, boolean antiWAF) {
        this.left = left;
        this.right = right;
        this.title = title;
        this.antiWAF = antiWAF;
    }

    public RespPair attempt(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        byte[] good = iScannerInsertionPoint.buildRequest(left.getBytes());
        byte[] bad = iScannerInsertionPoint.buildRequest(right.getBytes());
        result = new RespPair(good, bad, baseRequestResponse.getHttpService());

        if (antiWAF && (result.codeDiff || result.timingDiff)) {
            good = Utilities.appendToQuery(baseRequestResponse.getRequest(), Utilities.generateCanary()+"="+left);
            bad = Utilities.appendToQuery(baseRequestResponse.getRequest(), Utilities.generateCanary()+"="+right);
            RespPair wafCheck = new RespPair(good, bad, baseRequestResponse.getHttpService());
            if (wafCheck.timingDiff || wafCheck.codeDiff) {
                isWAFFP = true;
            }
        }

        return result;
    }

    boolean valid() {
        if (result == null || isWAFFP) {
            return false;
        }
        if (result.codeDiff) {
            return false;
        }
        return result.timingDiff;
    }

    public String getLeft() {
        return left;
    }

    public String getRight() {
        return right;
    }

    public String getTitle() {
        return title;
    }
}

