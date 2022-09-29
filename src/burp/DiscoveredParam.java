package burp;

import java.util.ArrayList;
import java.util.Arrays;
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

    public DiscoveredParam(ArrayList<Attack> evidence, PayloadInjector injector, String name, Attack failAttack, Attack workedAttack, IHttpRequestResponse baseRequestResponse) {
        this.evidence = evidence;
        this.injector = injector;
        this.name = name;
        this.failAttack = failAttack;
        this.workedAttack = workedAttack;
        this.staticCanary = Utilities.globalSettings.getString("canary").getBytes();
        this.baseRequestResponse = baseRequestResponse;
        this.type = injector.getInsertionPoint().getInsertionPointType();
    }


    public void exploreAndReport() {
        try {
            explore();
        } catch (Exception e) {
            // don't let a broken exploration prevent an issue being reported
            Utilities.showError(e);
        }
        report();
    }

    public void explore() {
        if (type == Utilities.PARAM_HEADER || type == IParameter.PARAM_COOKIE) {
            cachePoisoned = cachePoison(injector, name, failAttack.getFirstRequest());
        }

        canSeeCache = canSeeCache(workedAttack.getFirstRequest().getResponse());
        IHttpRequestResponse scanBaseAttack = injector.probeAttack(name).getFirstRequest();
        ParamNameInsertionPoint insertionPoint = (ParamNameInsertionPoint) injector.getInsertionPoint();
        IScannerInsertionPoint valueInsertionPoint = insertionPoint.getValueInsertionPoint(name);

        if (type == Utilities.PARAM_HEADER) {
            urlDecodes = ValueProbes.urlDecodes(scanBaseAttack, valueInsertionPoint);
        }
        pingback = ValueProbes.triggersPingback(scanBaseAttack, valueInsertionPoint);

        if (type == Utilities.PARAM_HEADER && !Utilities.containsBytes(workedAttack.getFirstRequest().getResponse(), staticCanary)) {
            return;
        }

        if (Utilities.globalSettings.getBoolean("probe identified params") && insertionPoint.type != Utilities.PARAM_HEADER) {
            for (Scan scan : BulkScan.scans) {
                if (scan instanceof ParamScan) {
                    ((ParamScan) scan).doActiveScan(scanBaseAttack, valueInsertionPoint);
                }
            }
        }

        if (!Utilities.globalSettings.getBoolean("scan identified params")) {
            return;
        }

        if (!Utilities.isBurpPro()) {
            Utilities.out("Can't autoscan identified parameter - requires pro edition");
            return;
        }

        IHttpService service = scanBaseAttack.getHttpService();
        //Utilities.callbacks.doActiveScan(service.getHost(), service.getPort(), Utilities.isHTTPS(service), req, offsets);
        //ValueGuesser.guessValue(scanBaseAttack, start, end);

    }

    public void report() {
        if (Utilities.globalSettings.getBoolean("poison only")) {
            return;
        }

        String typeName = Utilities.getNameFromType(type);
        String title = "Secret input: " + typeName;
        if (!cachePoisoned && canSeeCache) {
            title = "Secret uncached input: " + typeName;
        }

        if (Utilities.globalSettings.getBoolean("name in issue")) {
            title += ": " + name.split("~")[0];
        }

        if (pingback) {
            title += " [pingback]";
        }

        Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(evidence.toArray(new Attack[2]), baseRequestResponse, title, "Unlinked parameter identified."));
    }


    private static boolean cachePoison(PayloadInjector injector, String param, IHttpRequestResponse baseResponse) {
        if (!Utilities.globalSettings.getBoolean("try cache poison")) {
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
            paramBase.addAttack(altInject.probeAttack(Utilities.generateCanary()));
            paramBase.addAttack(altInject.probeAttack(Utilities.generateCanary()));
            ArrayList<Attack> confirmed = altInject.fuzz(paramBase, validParam);
            if (!confirmed.isEmpty()) {
                Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), base, "Potentially swappable param", ""));
            }

            byte[] testReq = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param));
            testReq = Utilities.addCacheBuster(testReq, Utilities.generateCanary());

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

            String pathCacheBuster = Utilities.generateCanary() + ".jpg";

            //String path = Utilities.getPathFromRequest(base.getRequest());
            //byte[] base404 = Utilities.replaceFirst(base.getRequest(), path.getBytes(), (path+pathCacheBuster).getBytes());
            byte[] base404 = Utilities.appendToPath(base.getRequest(), pathCacheBuster);


            IHttpRequestResponse get404 = Scan.request(injector.getService(), base404);
            short get404Code = Utilities.helpers.analyzeResponse(get404.getResponse()).getStatusCode();


            IHttpRequestResponse testResp = Scan.request(injector.getService(), testReq);

            byte[] staticCanary = Utilities.globalSettings.getString("canary").getBytes();
            boolean reflectPoisonMightWork = Utilities.containsBytes(testResp.getResponse(), staticCanary);
            boolean statusPoisonMightWork = Utilities.helpers.analyzeResponse(baseResponse.getResponse()).getStatusCode() != Utilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode();


            ArrayList<String> suffixes = new ArrayList<>();
            ArrayList<String> suffixesWhich404 = new ArrayList<>();
            String[] potentialSuffixes = new String[]{"index.php/zxcvk.jpg", "zxcvk.jpg"};

            suffixes.add("");
            if (reflectPoisonMightWork) {
                for (String suffix : potentialSuffixes) {
                    testResp = Scan.request(injector.getService(), Utilities.appendToPath(testReq, suffix));
                    if (Utilities.containsBytes(testResp.getResponse(), staticCanary)) {
                        if (Utilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode() == 200) {
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

            Utilities.log("Dedicated: "+attackDedication);
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

                if (!reflectPoisonMightWork && !statusPoisonMightWork && Utilities.globalSettings.getBoolean("twitchy cache poison")) {
                    if (tryDiffCache(injector, param, attackDedication)) {
                        return true;
                    }
                }
            }

            Utilities.log("Failed cache poisoning check");
        }
        catch (java.lang.Exception e) {
            Utilities.err(e.getMessage()+"\n\n"+e.getStackTrace()[0]);
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
        String canary = Utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param));
        setPoison200Req = Utilities.appendToPath(setPoison200Req, canary);
        for(int j=0; j<attackDedication; j++) {
            Scan.request(injector.getService(), setPoison200Req);
        }

        byte[] getPoisonReq = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes("z"+param+"z"));

        IHttpRequestResponse getPoisoned = Scan.request(injector.getService(), Utilities.appendToPath(getPoisonReq, canary));

        IResponseVariations baseline = Utilities.helpers.analyzeResponseVariations();
        IResponseVariations poisoned = Utilities.helpers.analyzeResponseVariations(getPoisoned.getResponse());
        IHttpRequestResponse resp = null;
        boolean diff = false;
        HashSet<String> diffed = new HashSet<>();
        for(int i=0; i<10; i++) {
            diffed.clear();
            diff = false;
            byte[] fakePoisonReq =  Utilities.appendToPath(getPoisonReq, Utilities.generateCanary()+".jpg");
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
            Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoisoned.getHttpService(), Utilities.getURL(getPoisoned), attachedRequests, "Attribute-diff cache poisoning: "+param, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming "+diffed, "High", "Tentative", "Investigate"));
            return true;
        }

        return false;
    }

    private static boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, short get404Code) {
        String canary = Utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(addStatusPayload(param)));
        setPoison200Req = Utilities.appendToPath(setPoison200Req, canary);

        byte[] getPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(addStatusPayload("xyz"+param+"z")));
        getPoison200Req = Utilities.appendToPath(getPoison200Req, canary);

        for(int j=0; j<attackDedication; j++) {
            Scan.request(injector.getService(), setPoison200Req);
        }

        for(int j=0; j<attackDedication; j+=3) {
            IHttpRequestResponse getPoison200 = Scan.request(injector.getService(), getPoison200Req);
            short getPoison200Code = Utilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
            if (getPoison200Code != get404Code) {
                Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), Utilities.getURL(getPoison200), getPoison200, "Status-code cache poisoning " + j, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
            }
            return true;
        }

        return false;
    }

//    private boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, String pathCacheBuster, byte[] base404, short get404Code, int i) {
//        IParameter cacheBuster = Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
//
//        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(addStatusPayload(param)));
//        setPoison200Req = Utilities.appendToPath(setPoison200Req, pathCacheBuster);
//
//        for(int j=attackDedication-i; j<attackDedication; j++) {
//            Scan.request(injector.getService(), Utilities.helpers.addParameter(setPoison200Req, cacheBuster));
//        }
//
//        for(int j=attackDedication-i; j<attackDedication; j+=3) {
//            IHttpRequestResponse getPoison200 = Scan.request(injector.getService(), Utilities.helpers.addParameter(base404, cacheBuster));
//            short getPoison200Code = Utilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
//
//            if (getPoison200Code != get404Code) {
//                Utilities.log("Successful cache poisoning check");
//                Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), Utilities.getURL(getPoison200), getPoison200, "Dubious cache poisoning "+i, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
//                return true;
//            }
//        }
//        return false;
//    }

    private static boolean tryReflectCache(PayloadInjector injector, String param, IHttpRequestResponse base, int attackDedication, int i, String pathSuffix) {
        IHttpService service = injector.getService();
        byte[] setPoisonReq = Utilities.appendToPath(injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param)), pathSuffix);

        String cacheBuster = Utilities.generateCanary();
        setPoisonReq = Utilities.addCacheBuster(setPoisonReq, cacheBuster);
        for (int j = attackDedication - i; j < attackDedication; j++) {
            Scan.request(service, setPoisonReq);
        }

        byte[] staticCanary = Utilities.globalSettings.getString("canary").getBytes();
        for (int j = attackDedication - i; j < attackDedication; j += 3) {
            IHttpRequestResponse getPoison = Scan.request(service, Utilities.appendToPath(Utilities.addCacheBuster(base.getRequest(), cacheBuster), pathSuffix));
            if (Utilities.containsBytes(getPoison.getResponse(), staticCanary)) {
                Utilities.log("Successful cache poisoning check");
                String title = "Cache poisoning";

                byte[] headerSplitReq = Utilities.appendToPath(injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param + "~zxcv\rvcz")), pathSuffix);
                cacheBuster = Utilities.generateCanary();
                byte[] headerSplitResp = Scan.request(service, Utilities.addCacheBuster(headerSplitReq, cacheBuster)).getResponse();
                if (Utilities.containsBytes(Arrays.copyOfRange(headerSplitResp, 0, Utilities.getBodyStart(headerSplitReq)), "zxcv\rvcz".getBytes())) {
                    title = "Severe cache poisoning";
                }

                title = title + " "+i;
                Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison.getHttpService(), Utilities.getURL(getPoison), getPoison, title, "Cache poisoning: '" + param + "'. Disregard the request and look for "+new String(staticCanary)+" in the response", "High", "Firm", "Investigate"));
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
            if(Utilities.getHeaderOffsets(response, header) != null) {
                return true;
            }
        }
        return false;
    }

}
