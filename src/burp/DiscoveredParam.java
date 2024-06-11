package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

public class DiscoveredParam {
    ArrayList<Attack> evidence;
    Attack failAttack;
    Attack workedAttack;
    PayloadInjector injector;
    String name;
    byte[] staticCanary;
    IHttpRequestResponse baseRequestResponse;
    byte type;

    boolean canSeeCache = false;
    boolean cachePoisoned = false;

    boolean urlDecodes = false;
    boolean eatsSlash = false;
    boolean pingback = false;
    boolean dynamicOnly = false;
    boolean magicIP = false;

    public DiscoveredParam(ArrayList<Attack> evidence, PayloadInjector injector, String name, Attack failAttack, Attack workedAttack, IHttpRequestResponse baseRequestResponse) {
        this.evidence = evidence;
        this.injector = injector;
        this.name = name;
        this.failAttack = failAttack;
        this.workedAttack = workedAttack;
        this.staticCanary = BulkUtilities.globalSettings.getString("canary").getBytes();
        this.baseRequestResponse = baseRequestResponse;
        this.type = injector.getInsertionPoint().getInsertionPointType();
    }


    public void exploreAndReport() {
        try {
            explore();
        } catch (Exception e) {
            // don't let a broken exploration prevent an issue being reported
            BulkUtilities.showError(e);
        }
        report();
    }

    public void explore() {

        if (type == BulkUtilities.PARAM_HEADER || type == IParameter.PARAM_COOKIE) {
            cachePoisoned = cachePoison(injector, name, failAttack.getFirstRequest());
        }

        canSeeCache = canSeeCache(workedAttack.getFirstRequest().getResponse());
        IHttpRequestResponse scanBaseAttack = injector.probeAttack(name).getFirstRequest();
        ParamNameInsertionPoint insertionPoint = (ParamNameInsertionPoint) injector.getInsertionPoint();
        RawInsertionPoint valueInsertionPoint = insertionPoint.getValueInsertionPoint(name);

        if (type == BulkUtilities.PARAM_HEADER) {
            urlDecodes = ValueProbes.urlDecodes(scanBaseAttack, valueInsertionPoint);
        }

        ValueProbes.eatsBackslash(scanBaseAttack, valueInsertionPoint);
        pingback = ValueProbes.triggersPingback(scanBaseAttack, valueInsertionPoint);
        dynamicOnly = ValueProbes.dynamicOnly(injector, name);
        magicIP = ValueProbes.magicIP(injector, name);

        ValueProbes.utf8(scanBaseAttack, valueInsertionPoint);
        ValueProbes.utf82(scanBaseAttack, valueInsertionPoint);

//        if (type == BulkUtilities.PARAM_HEADER && !BulkUtilities.containsBytes(workedAttack.getFirstRequest().getResponse(), staticCanary)) {
//            return;
//        }

        if (BulkUtilities.globalSettings.getBoolean("probe identified params") && insertionPoint.type != BulkUtilities.PARAM_HEADER) {
            for (Scan scan : BulkScan.scans) {
                if (scan instanceof ParamScan) {
                    ((ParamScan) scan).doActiveScan(scanBaseAttack, valueInsertionPoint);
                }
            }
        }

        if (!BulkUtilities.globalSettings.getBoolean("scan identified params")) {
            return;
        }

        if (!BulkUtilities.isBurpPro()) {
            BulkUtilities.out("Can't autoscan identified parameter - requires pro edition");
            return;
        }

        IHttpService service = scanBaseAttack.getHttpService();
        BulkUtilities.callbacks.doActiveScan(service.getHost(), service.getPort(), BulkUtilities.isHTTPS(service), valueInsertionPoint.req, Collections.singletonList(new int[]{valueInsertionPoint.start, valueInsertionPoint.end}));
        //ValueGuesser.guessValue(scanBaseAttack, start, end);

    }

    public void report() {
        if (BulkUtilities.globalSettings.getBoolean("poison only")) {
            return;
        }

        String typeName = BulkUtilities.getNameFromType(type);
        String title = "Secret input: " + typeName;
        if (!cachePoisoned && canSeeCache) {
            title = "Secret uncached input: " + typeName;
        }

        if (BulkUtilities.globalSettings.getBoolean("name in issue")) {
            title += ": " + name.split("~")[0];
        }

        if (pingback) {
            title += " [pingback]";
        }

        if (dynamicOnly) {
            title += " [dynamic-only]";
        }

        if (magicIP) {
            title += " [magic-ip]";
        }

        BulkUtilities.callbacks.addScanIssue(BulkUtilities.reportReflectionIssue(evidence.toArray(new Attack[2]), baseRequestResponse, title, "Unlinked parameter identified."));
    }


    private static boolean cachePoison(PayloadInjector injector, String param, IHttpRequestResponse baseResponse) {
        if (!BulkUtilities.globalSettings.getBoolean("try cache poison")) {
            return false;
        }

        try {
            IHttpRequestResponse base = injector.getBase();
            PayloadInjector altInject = new PayloadInjector(base, new ParamNameInsertionPoint(base.getRequest(), "guesser", "", IParameter.PARAM_URL, "repliblah"));
            Probe validParam = new Probe("Potentially swappable param: " + param, 5, param);
            validParam.setEscapeStrings(Keysmith.permute(param), Keysmith.permute(param, false));
            validParam.setRandomAnchor(false);
            validParam.setPrefix(Probe.REPLACE);
            Attack paramBase = new Attack();
            paramBase.addAttack(altInject.probeAttack(BulkUtilities.generateCanary()));
            paramBase.addAttack(altInject.probeAttack(BulkUtilities.generateCanary()));
            ArrayList<Attack> confirmed = altInject.fuzz(paramBase, validParam);
            if (!confirmed.isEmpty()) {
                BulkUtilities.callbacks.addScanIssue(BulkUtilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), base, "Potentially swappable param", ""));
            }

            byte[] testReq = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(param));
            testReq = BulkUtilities.addCacheBuster(testReq, BulkUtilities.generateCanary());

            int attackDedication;
            if (canSeeCache(base.getResponse())) {
                attackDedication = 10;
            }
            else {
                attackDedication = 5;
                for (int i=0;i<5;i++) {
                    IHttpRequestResponse base2 = Scan.request(injector.getService(), testReq);
                    if (canSeeCache(base2.getResponse())) {
                        attackDedication = 30;
                        break;
                    }
                }
            }

            String pathCacheBuster = BulkUtilities.generateCanary() + ".jpg";

            //String path = BulkUtilities.getPathFromRequest(base.getRequest());
            //byte[] base404 = BulkUtilities.replaceFirst(base.getRequest(), path.getBytes(), (path+pathCacheBuster).getBytes());
            byte[] base404 = BulkUtilities.appendToPath(base.getRequest(), pathCacheBuster);


            IHttpRequestResponse get404 = Scan.request(injector.getService(), base404);
            short get404Code = BulkUtilities.helpers.analyzeResponse(get404.getResponse()).getStatusCode();


            IHttpRequestResponse testResp = Scan.request(injector.getService(), testReq);

            byte[] staticCanary = BulkUtilities.globalSettings.getString("canary").getBytes();
            boolean reflectPoisonMightWork = BulkUtilities.containsBytes(testResp.getResponse(), staticCanary);
            boolean statusPoisonMightWork = BulkUtilities.helpers.analyzeResponse(baseResponse.getResponse()).getStatusCode() != BulkUtilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode();


            ArrayList<String> suffixes = new ArrayList<>();
            ArrayList<String> suffixesWhich404 = new ArrayList<>();
            String[] potentialSuffixes = new String[]{"index.php/zxcvk.jpg", "zxcvk.jpg"};

            suffixes.add("");
            if (reflectPoisonMightWork) {
                for (String suffix : potentialSuffixes) {
                    testResp = Scan.request(injector.getService(), BulkUtilities.appendToPath(testReq, suffix));
                    if (BulkUtilities.containsBytes(testResp.getResponse(), staticCanary)) {
                        if (BulkUtilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode() == 200) {
                            suffixes.add(suffix);
                        } else {
                            suffixesWhich404.add(suffix);
                        }
                    }
                    if (attackDedication == 2 && canSeeCache(testResp.getResponse())) {
                        attackDedication = 7;
                    }
                }
            }

            if (suffixes.size() == 1) {
                if (!suffixesWhich404.isEmpty()) {
                    suffixes.add(suffixesWhich404.get(suffixesWhich404.size() - 1));
                }
            }

            BulkUtilities.log("Dedicated: "+attackDedication);
            for (int i = 1; i < attackDedication; i++) {

                if (reflectPoisonMightWork) {
                    for (String suffix : suffixes) {
                        if (tryReflectCache(injector, param, base, attackDedication, i, suffix)) return true;
                    }
                }

                if (statusPoisonMightWork) {
                    //if (tryStatusCache(injector, param, attackDedication, pathCacheBuster, base404, get404Code, i))
                    if (tryStatusCache(injector, param, attackDedication, get404Code))
                        return true;
                }

                if (!reflectPoisonMightWork && !statusPoisonMightWork && BulkUtilities.globalSettings.getBoolean("twitchy cache poison")) {
                    if (tryDiffCache(injector, param, attackDedication)) {
                        return true;
                    }
                }
            }

            BulkUtilities.log("Failed cache poisoning check");
        }
        catch (java.lang.Exception e) {
            BulkUtilities.err(e.getMessage()+"\n\n"+e.getStackTrace()[0]);
        }
        return false;
    }

    private static String addStatusPayload(String paramName) {
        if (paramName.contains("~")) {
            return paramName;
        }
        else if (paramName.equals("x-original-url")) {
            return paramName+"~/";
        }
        else {
            return paramName;
        }
    }

    private static boolean tryDiffCache(PayloadInjector injector, String param, int attackDedication) {
        String canary = BulkUtilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(param));
        setPoison200Req = BulkUtilities.appendToPath(setPoison200Req, canary);
        for(int j=0; j<attackDedication; j++) {
            Scan.request(injector.getService(), setPoison200Req);
        }

        byte[] getPoisonReq = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes("z"+param+"z"));

        IHttpRequestResponse getPoisoned = Scan.request(injector.getService(), BulkUtilities.appendToPath(getPoisonReq, canary));

        IResponseVariations baseline = BulkUtilities.helpers.analyzeResponseVariations();
        IResponseVariations poisoned = BulkUtilities.helpers.analyzeResponseVariations(getPoisoned.getResponse());
        IHttpRequestResponse resp = null;
        boolean diff = false;
        HashSet<String> diffed = new HashSet<>();
        for(int i=0; i<10; i++) {
            diffed.clear();
            diff = false;
            byte[] fakePoisonReq =  BulkUtilities.appendToPath(getPoisonReq, BulkUtilities.generateCanary()+".jpg");
            resp = Scan.request(injector.getService(), fakePoisonReq);
            baseline.updateWith(resp.getResponse());
            for (String attribute: baseline.getInvariantAttributes()) {
                if (baseline.getAttributeValue(attribute, 0) != poisoned.getAttributeValue(attribute, 0)) {
                    diff = true;
                    diffed.add(attribute);
                }
            }
            if (!diff) {
                break;
            }
        }

        if (diff) {
            IHttpRequestResponse[] attachedRequests = new IHttpRequestResponse[2];
            attachedRequests[0] = resp;
            attachedRequests[1] = getPoisoned;
            BulkUtilities.callbacks.addScanIssue(new CustomScanIssue(getPoisoned.getHttpService(), BulkUtilities.getURL(getPoisoned), attachedRequests, "Attribute-diff cache poisoning: "+param, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming "+diffed, "High", "Tentative", "Investigate"));
            return true;
        }

        return false;
    }

    private static boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, short get404Code) {
        String canary = BulkUtilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(addStatusPayload(param)));
        setPoison200Req = BulkUtilities.appendToPath(setPoison200Req, canary);

        byte[] getPoison200Req = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(addStatusPayload("xyz"+param+"z")));
        getPoison200Req = BulkUtilities.appendToPath(getPoison200Req, canary);

        for(int j=0; j<attackDedication; j++) {
            Scan.request(injector.getService(), setPoison200Req);
        }

        for(int j=0; j<attackDedication; j+=3) {
            IHttpRequestResponse getPoison200 = Scan.request(injector.getService(), getPoison200Req);
            short getPoison200Code = BulkUtilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
            if (getPoison200Code != get404Code) {
                BulkUtilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), BulkUtilities.getURL(getPoison200), getPoison200, "Status-code cache poisoning " + j, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
            }
            return true;
        }

        return false;
    }

//    private boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, String pathCacheBuster, byte[] base404, short get404Code, int i) {
//        IParameter cacheBuster = BulkUtilities.helpers.buildParameter(BulkUtilities.generateCanary(), "1", IParameter.PARAM_URL);
//
//        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(addStatusPayload(param)));
//        setPoison200Req = BulkUtilities.appendToPath(setPoison200Req, pathCacheBuster);
//
//        for(int j=attackDedication-i; j<attackDedication; j++) {
//            Scan.request(injector.getService(), BulkUtilities.helpers.addParameter(setPoison200Req, cacheBuster));
//        }
//
//        for(int j=attackDedication-i; j<attackDedication; j+=3) {
//            IHttpRequestResponse getPoison200 = Scan.request(injector.getService(), BulkUtilities.helpers.addParameter(base404, cacheBuster));
//            short getPoison200Code = BulkUtilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
//
//            if (getPoison200Code != get404Code) {
//                BulkUtilities.log("Successful cache poisoning check");
//                BulkUtilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), BulkUtilities.getURL(getPoison200), getPoison200, "Dubious cache poisoning "+i, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
//                return true;
//            }
//        }
//        return false;
//    }

    private static boolean tryReflectCache(PayloadInjector injector, String param, IHttpRequestResponse base, int attackDedication, int i, String pathSuffix) {
        IHttpService service = injector.getService();
        byte[] setPoisonReq = BulkUtilities.appendToPath(injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(param)), pathSuffix);

        String cacheBuster = BulkUtilities.generateCanary();
        setPoisonReq = BulkUtilities.addCacheBuster(setPoisonReq, cacheBuster);
        for (int j = attackDedication - i; j < attackDedication; j++) {
            Scan.request(service, setPoisonReq);
        }

        byte[] staticCanary = BulkUtilities.globalSettings.getString("canary").getBytes();
        for (int j = attackDedication - i; j < attackDedication; j += 3) {
            IHttpRequestResponse getPoison = Scan.request(service, BulkUtilities.appendToPath(BulkUtilities.addCacheBuster(base.getRequest(), cacheBuster), pathSuffix));
            if (BulkUtilities.containsBytes(getPoison.getResponse(), staticCanary)) {
                BulkUtilities.log("Successful cache poisoning check");
                String title = "Cache poisoning";

                byte[] headerSplitReq = BulkUtilities.appendToPath(injector.getInsertionPoint().buildRequest(BulkUtilities.helpers.stringToBytes(param + "~zxcv\rvcz")), pathSuffix);
                cacheBuster = BulkUtilities.generateCanary();
                byte[] headerSplitResp = Scan.request(service, BulkUtilities.addCacheBuster(headerSplitReq, cacheBuster)).getResponse();
                if (BulkUtilities.containsBytes(Arrays.copyOfRange(headerSplitResp, 0, BulkUtilities.getBodyStart(headerSplitReq)), "zxcv\rvcz".getBytes())) {
                    title = "Severe cache poisoning";
                }

                title = title + " "+i;
                BulkUtilities.callbacks.addScanIssue(new CustomScanIssue(getPoison.getHttpService(), BulkUtilities.getURL(getPoison), getPoison, title, "Cache poisoning: '" + param + "'. Disregard the request and look for "+new String(staticCanary)+" in the response", "High", "Firm", "Investigate"));
                return true;
            }
        }
        return false;
    }


    private static boolean canSeeCache(byte[] response) {
        if (response == null) {
            return false;
        }
        String[] headers = new String[]{"Age", "X-Cache", "Cache", "X-Cache-Hits", "X-Varnish-Cache", "X-Drupal-Cache", "X-Varnish", "CF-Cache-Status", "CF-RAY"};
        for(String header: headers) {
            if(BulkUtilities.getHeaderOffsets(response, header) != null) {
                return true;
            }
        }
        return false;
    }

}
