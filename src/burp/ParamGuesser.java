package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;


class SimpleScan implements Runnable, IExtensionStateListener {

    public void run() {

    }

    public void extensionUnloaded() {
        Utilities.log("Aborting param bruteforce");
        Utilities.unloaded.set(true);
    }

}
/**
 * Created by james on 30/08/2017.
 */
class ParamGuesser implements Runnable {

    private IHttpRequestResponse req;
    private boolean backend;
    private byte type;
    private ThreadPoolExecutor taskEngine;
    private int stop;
    private ParamGrabber paramGrabber;
    private ParamAttack attack;
    private ConfigurableSettings config;

    ParamGuesser(IHttpRequestResponse req, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine, int stop, ConfigurableSettings config) {
        this.paramGrabber = paramGrabber;
        this.req = req;
        this.backend = backend;
        this.type = type;
        this.stop = stop;
        this.taskEngine = taskEngine;
        this.config = config;
    }

    ParamGuesser(ParamAttack attack, ThreadPoolExecutor taskEngine, ConfigurableSettings config) {
        this.attack = attack;
        this.req = attack.getBaseRequestResponse();
        this.taskEngine = taskEngine;
        this.config = config;
    }

    public void run() {
        if(this.attack == null) {
            if (req.getResponse() == null) {
                Utilities.log("Baserequest has no response - fetching...");
                try {
                    req = Utilities.callbacks.makeHttpRequest(req.getHttpService(), req.getRequest());
                }
                catch (RuntimeException e) {
                    Utilities.out("Aborting attack due to failed lookup");
                    return;
                }
                if (req == null) {
                    Utilities.out("Aborting attack due to null response");
                    return;
                }
            }
            this.attack = new ParamAttack(req, type, paramGrabber, stop, config);
        }
        ArrayList<Attack> paramGuesses = guessParams(attack);
        if (!paramGuesses.isEmpty()) {
            Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req));
        }

//        if(backend) {
//            IRequestInfo info = Utilities.helpers.analyzeRequest(req);
//            List<IParameter> params = info.getParameters();
//            for (IParameter param : params) {
//                String key = null;
//                String[] keys = {"%26zq=%253c", "!zq=%253c"};
//                for (String test : keys) {
//                    if (param.getValue().contains(test)) {
//                        key = test;
//                        break;
//                    }
//                }
//
//                if (key != null) {
//                    String originalValue = param.getValue().substring(0, param.getValue().indexOf(key));
//                    ParamInsertionPoint insertionPoint = new ParamInsertionPoint(req.getRequest(), param.getName(), originalValue, param.getType());
//                    ArrayList<Attack> paramGuesses = guessBackendParams(req, insertionPoint);
//                    if (!paramGuesses.isEmpty()) {
//                        Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req));
//                    }
//                    break;
//                }
//
//            }
//        }
    }

    private ArrayList<Attack> guessParams(ParamAttack state) {
        final int bucketSize = state.getBucketSize();
        final IHttpRequestResponse baseRequestResponse = state.getBaseRequestResponse();
        final IHttpService service = baseRequestResponse.getHttpService();
        final PayloadInjector injector = state.getInjector();
        final String attackID = state.getAttackID();
        final String targetURL = state.getTargetURL();
        final boolean tryMethodFlip = state.shouldTryMethodFlip();
        final ParamInsertionPoint insertionPoint = state.getInsertionPoint();
        final HashMap<String, String> requestParams = state.getRequestParams();
        final WordProvider bonusParams = state.getBonusParams();
        final byte type = state.type;

        ArrayList<Attack> attacks = new ArrayList<>();
        int completedAttacks = 0;
        int start = 0; // todo could manually set this
        int stop = state.getStop();
        Attack base = state.getBase();
        byte[] invertedBase = state.getInvertedBase();
        Attack altBase = state.getAltBase();
        ParamHolder paramBuckets = state.getParamBuckets();

        if (!state.started) {
            Utilities.out("Initiating "+Utilities.getNameFromType(type)+" bruteforce on "+ targetURL);
            state.started = true;
        }
        else {
            Utilities.out("Resuming "+Utilities.getNameFromType(type)+" bruteforce at "+state.seed+" on "+ targetURL);
        }


        while (completedAttacks++ < stop) {
            if (paramBuckets.size() == 0) {
                ArrayList<String> newParams = new ArrayList<>();
                int i = 0;
                if (state.seed == -1) {
                    while (i++ < bucketSize) {
                        String next = bonusParams.getNext();
                        if (next == null) {
                            state.seed = 0;
                            break;
                        }
                        newParams.add(next);
                    }
                }
                else {
                    if (!config.getBoolean("bruteforce")) {
                        Utilities.out("Completed attack on "+ targetURL);
                        return attacks;
                    }
                    state.seed = Utilities.generate(state.seed, bucketSize, newParams);
                }
                newParams.removeAll(state.alreadyReported);
                paramBuckets.addParams(newParams, true);
            }

            ArrayList<String> candidates;
            try {
                candidates = paramBuckets.pop();
            }
            catch (NoSuchElementException e) {
                continue;
            }

            if (completedAttacks < start) {
                continue;
            }

            //candidates.remove("");
            candidates.removeAll(state.alreadyReported);
            candidates.removeIf((String candidate) -> (candidate.contains("_") && state.alreadyReported.contains(candidate.replace('_', '-'))));
            candidates.removeIf((String candidate) -> (candidate.contains("~") && state.alreadyReported.contains(candidate.split("~", 2)[0])));
            if (candidates.isEmpty()) {
                continue;
            }

            String submission = String.join("|", candidates);
            Attack paramGuess = injector.probeAttack(submission);

            if (!candidates.contains("~")) {
                if (findPersistent(baseRequestResponse, paramGuess, attackID, state.recentParams, candidates, state.alreadyReported)) {
                    state.updateBaseline();
                }
                state.recentParams.addAll(candidates); // fixme this results in params being found multiple times
            }

            Attack localBase;
            if (submission.contains("~")) {
                localBase = new Attack();
                localBase.addAttack(base);
            }
            else {
                localBase = base;
            }

            if (!Utilities.globalSettings.getBoolean("carpet bomb") && !Utilities.similar(localBase, paramGuess)) {
                Attack confirmParamGuess = injector.probeAttack(submission);

                Attack failAttack = injector.probeAttack(Keysmith.permute(submission));

                // this to prevent error messages obscuring persistent inputs
                findPersistent(baseRequestResponse, failAttack, attackID, state.recentParams, null, state.alreadyReported);

                localBase.addAttack(failAttack);
                if (!Utilities.similar(localBase, confirmParamGuess)) {

                    if(candidates.size() > 1) {
                        Utilities.log("Splitting "+ submission);
                        ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                        Utilities.log("Got "+String.join("|",left));
                        ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2, candidates.size()));
                        Utilities.log("Got "+String.join("|",right));
                        paramBuckets.push(left);
                        paramBuckets.push(right);
                    }
                    else {
                        if (state.alreadyReported.contains(submission)) {
                            continue;
                        }

                        Attack WAFCatcher = new Attack(Utilities.attemptRequest(service, Utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-header", submission)));
                        WAFCatcher.addAttack(new Attack(Utilities.attemptRequest(service, Utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-head", submission))));
                        if (!Utilities.similar(WAFCatcher, confirmParamGuess)){
                            Probe validParam = new Probe("Found unlinked param: " + submission, 4, submission);
                            validParam.setEscapeStrings(Keysmith.permute(submission), Keysmith.permute(submission, false));
                            validParam.setRandomAnchor(false);
                            validParam.setPrefix(Probe.REPLACE);
                            ArrayList<Attack> confirmed = injector.fuzz(localBase, validParam);
                            if (!confirmed.isEmpty()) {
                                state.alreadyReported.add(submission);
                                Utilities.reportedParams.add(submission);
                                Utilities.out("Identified parameter on "+targetURL + ": " + submission);

                                boolean cacheSuccess = false;
                                if (type == Utilities.PARAM_HEADER || type == IParameter.PARAM_COOKIE) {
                                    cacheSuccess = cachePoison(injector, submission, failAttack.getFirstRequest());
                                }

                                if (!Utilities.CACHE_ONLY) {
                                    String title = "Secret input: " + Utilities.getNameFromType(type);
                                    if (!cacheSuccess && canSeeCache(paramGuess.getFirstRequest().getResponse())) {
                                        title = "Secret uncached input: " + Utilities.getNameFromType(type);
                                    }
                                    if (Utilities.globalSettings.getBoolean("name in issue")) {
                                        title +=  ": " + submission.split("~")[0];
                                    }
                                    Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), baseRequestResponse, title));

                                    if (true || type != Utilities.PARAM_HEADER || Utilities.containsBytes(paramGuess.getFirstRequest().getResponse(), "wrtqva".getBytes())) {
                                        scanParam(insertionPoint, injector, submission.split("~", 2)[0]);
                                    }

                                    base = state.updateBaseline();
                                }

                                //Utilities.callbacks.doPassiveScan(service.getHost(), service.getPort(), service.getProtocol().equals("https"), paramGuess.getFirstRequest().getRequest(), paramGuess.getFirstRequest().getResponse());

                                if (config.getBoolean("dynamic keyload")) {
                                    ArrayList<String> newWords = new ArrayList<>(Keysmith.getWords(Utilities.helpers.bytesToString(paramGuess.getFirstRequest().getResponse())));
                                    addNewKeys(newWords, state, bucketSize, paramBuckets, candidates, paramGuess);
                                }
                            } else {
                                Utilities.out(targetURL + " questionable parameter: " + candidates);
                            }
                        }
                    }
                } else {
                    Utilities.log(targetURL + " couldn't replicate: " + candidates);
                    base.addAttack(paramGuess);
                }

                if(config.getBoolean("dynamic keyload")) {
                    addNewKeys(Keysmith.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams), state, bucketSize, paramBuckets, candidates, paramGuess);
                }

            } else if (tryMethodFlip) {
                Attack paramGrab = new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase));
                findPersistent(baseRequestResponse, paramGrab, attackID, state.recentParams, null, state.alreadyReported);

                if (!Utilities.similar(altBase, paramGrab)) {
                    Utilities.log("Potential GETbase param: " + candidates);
                    injector.probeAttack(Keysmith.permute(submission));
                    altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase)));
                    injector.probeAttack(submission);

                    paramGrab = new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase));
                    if (!Utilities.similar(altBase, paramGrab)) {

                        if(candidates.size() > 1) {
                            Utilities.log("Splitting "+ submission);
                            ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                            ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2 + 1, candidates.size()));
                            paramBuckets.push(left);
                            paramBuckets.push(right);
                        }
                        else {
                            Utilities.out("Confirmed GETbase param: " + candidates);
                            IHttpRequestResponse[] evidence = new IHttpRequestResponse[3];
                            evidence[0] = altBase.getFirstRequest();
                            evidence[1] = paramGuess.getFirstRequest();
                            evidence[2] = paramGrab.getFirstRequest();
                            Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(baseRequestResponse), evidence, "Secret parameter", "Parameter name: '" + candidates + "'. Review the three requests attached in chronological order.", "Medium", "Tentative", "Investigate"));

                            altBase = new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase));
                            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase)));
                            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase)));
                            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(service, invertedBase)));
                        }
                    }
                }
            }
        }


        state.incrStop();
        taskEngine.execute(new ParamGuesser(state, taskEngine, config));

        return attacks;
    }

    private boolean cachePoison(PayloadInjector injector, String param, IHttpRequestResponse baseResponse) {
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
                Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), base, "Potentially swappable param"));
            }

            byte[] testReq = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param));
            IParameter testCacheBuster = Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
            testReq = Utilities.helpers.addParameter(testReq, testCacheBuster);

            int attackDedication;
            if (canSeeCache(base.getResponse())) {
                attackDedication = 30;
            }
            else {
                attackDedication = 5;
                for (int i=0;i<5;i++) {
                    IHttpRequestResponse base2 = Utilities.attemptRequest(injector.getService(), testReq);
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


            IHttpRequestResponse get404 = Utilities.attemptRequest(injector.getService(), base404);
            short get404Code = Utilities.helpers.analyzeResponse(get404.getResponse()).getStatusCode();


            IHttpRequestResponse testResp = Utilities.attemptRequest(injector.getService(), testReq);

            boolean reflectPoisonMightWork = Utilities.containsBytes(testResp.getResponse(), "wrtqv".getBytes());
            boolean statusPoisonMightWork = Utilities.helpers.analyzeResponse(baseResponse.getResponse()).getStatusCode() != Utilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode();


            ArrayList<String> suffixes = new ArrayList<>();
            ArrayList<String> suffixesWhich404 = new ArrayList<>();
            String[] potentialSuffixes = new String[]{"index.php/zxcvk.jpg", "zxcvk.jpg"};

            suffixes.add("");
            if (reflectPoisonMightWork) {
                for (String suffix : potentialSuffixes) {
                    testResp = Utilities.attemptRequest(injector.getService(), Utilities.appendToPath(testReq, suffix));
                    if (Utilities.containsBytes(testResp.getResponse(), "wrtqv".getBytes())) {
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

            // fixme remove this
            reflectPoisonMightWork = false;
            statusPoisonMightWork = false;

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

                if (!reflectPoisonMightWork && !statusPoisonMightWork) {
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

    private String addStatusPayload(String paramName) {
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

    private boolean tryDiffCache(PayloadInjector injector, String param, int attackDedication) {
        String canary = Utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param));
        setPoison200Req = Utilities.appendToPath(setPoison200Req, canary);
        for(int j=0; j<attackDedication; j++) {
            Utilities.attemptRequest(injector.getService(), setPoison200Req);
        }

        byte[] getPoisonReq = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes("z"+param+"z"));
        byte[] fakePoisonReq =  Utilities.appendToPath(getPoisonReq, Utilities.generateCanary()+".jpg");
        getPoisonReq = Utilities.appendToPath(getPoisonReq, canary);
        IHttpRequestResponse getPoisoned = Utilities.attemptRequest(injector.getService(), getPoisonReq);

        IResponseVariations baseline = Utilities.helpers.analyzeResponseVariations();
        IResponseVariations poisoned = Utilities.helpers.analyzeResponseVariations(getPoisoned.getResponse());
        boolean diff = false;
        HashSet<String> diffed = new HashSet<>();
        for(int i=0; i<10; i++) {
            diffed.clear();
            diff = false;
            baseline.updateWith(Utilities.attemptRequest(injector.getService(), fakePoisonReq).getResponse());
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
            Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoisoned.getHttpService(), Utilities.getURL(getPoisoned), getPoisoned, "Extra Dubious cache poisoning ", "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming "+diffed, "High", "Tentative", "Investigate"));
            return true;
        }

        return false;
    }

    private boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, short get404Code) {
        String canary = Utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(addStatusPayload(param)));
        setPoison200Req = Utilities.appendToPath(setPoison200Req, canary);

        byte[] getPoison200Req = injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(addStatusPayload("xyz"+param+"z")));
        getPoison200Req = Utilities.appendToPath(getPoison200Req, canary);

        for(int j=0; j<attackDedication; j++) {
            Utilities.attemptRequest(injector.getService(), setPoison200Req);
        }

        for(int j=0; j<attackDedication; j+=3) {
            IHttpRequestResponse getPoison200 = Utilities.attemptRequest(injector.getService(), getPoison200Req);
            short getPoison200Code = Utilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
            if (getPoison200Code != get404Code) {
                Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), Utilities.getURL(getPoison200), getPoison200, "Dubious cache poisoning " + j, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
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
//            Utilities.attemptRequest(injector.getService(), Utilities.helpers.addParameter(setPoison200Req, cacheBuster));
//        }
//
//        for(int j=attackDedication-i; j<attackDedication; j+=3) {
//            IHttpRequestResponse getPoison200 = Utilities.attemptRequest(injector.getService(), Utilities.helpers.addParameter(base404, cacheBuster));
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

    private boolean tryReflectCache(PayloadInjector injector, String param, IHttpRequestResponse base, int attackDedication, int i, String pathSuffix) {
        IHttpService service = injector.getService();
        byte[] setPoisonReq = Utilities.appendToPath(injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param)), pathSuffix);
        IParameter cacheBuster = Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
        setPoisonReq = Utilities.helpers.addParameter(setPoisonReq, cacheBuster);
        for (int j = attackDedication - i; j < attackDedication; j++) {
            Utilities.attemptRequest(service, setPoisonReq);
        }

        for (int j = attackDedication - i; j < attackDedication; j += 3) {
            IHttpRequestResponse getPoison = Utilities.attemptRequest(service, Utilities.appendToPath(Utilities.helpers.addParameter(base.getRequest(), cacheBuster), pathSuffix));
            if (Utilities.containsBytes(getPoison.getResponse(), "wrtqv".getBytes())) {
                Utilities.log("Successful cache poisoning check");
                String title = "Cache poisoning";

                byte[] headerSplitReq = Utilities.appendToPath(injector.getInsertionPoint().buildRequest(Utilities.helpers.stringToBytes(param + "~zxcv\rvcz")), pathSuffix);
                cacheBuster = Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
                byte[] headerSplitResp = Utilities.attemptRequest(service, Utilities.helpers.addParameter(headerSplitReq, cacheBuster)).getResponse();
                if (Utilities.containsBytes(Arrays.copyOfRange(headerSplitResp, 0, Utilities.getBodyStart(headerSplitReq)), "zxcv\rvcz".getBytes())) {
                    title = "Severe cache poisoning";
                }

                title = title + " "+i;
                Utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison.getHttpService(), Utilities.getURL(getPoison), getPoison, title, "Cache poisoning: '" + param + "'. Disregard the request and look for wrtqv in the response", "High", "Firm", "Investigate"));
                return true;
            }
        }
        return false;
    }


    private static boolean canSeeCache(byte[] response) {
        String[] headers = new String[]{"Age", "X-Cache", "Cache", "X-Cache-Hits", "X-Varnish-Cache", "X-Drupal-Cache", "X-Varnish", "CF-Cache-Status", "CF-RAY"};
        for(String header: headers) {
            if(Utilities.getHeaderOffsets(response, header) != null) {
                return true;
            }
        }
        return false;
    }

    private void addNewKeys(ArrayList<String> keys, ParamAttack state, int bucketSize, ParamHolder paramBuckets, ArrayList<String> candidates, Attack paramGuess) {
        if (!config.getBoolean("dynamic keyload")) {
            return;
        }
        ArrayList<String> discoveredParams = new ArrayList<>();
        for (String key : keys) {
            String[] parsed = Keysmith.parseKey(key);
            if (!(state.valueParams.contains(key) || state.params.contains(key) || candidates.contains(parsed[1]) || candidates.contains(key))) { // || params.contains(parsed[1])
                Utilities.log("Found new key: " + key);
                state.valueParams.add(key);
                discoveredParams.add(key); // fixme probably adds the key in the wrong format
                paramGrabber.saveParams(paramGuess.getFirstRequest());
            }
        }

        paramBuckets.addParams(discoveredParams, true);
    }

    private void scanParam(ParamInsertionPoint insertionPoint, PayloadInjector injector, String scanBasePayload) {
        if(!Utilities.globalSettings.getBoolean("scan identified params")) {
            return;
        }

        if (!Utilities.isBurpPro()) {
            Utilities.out("Can't autoscan identified parameter - requires pro edition");
            return;
        }

        IHttpRequestResponse scanBaseAttack = injector.probeAttack(scanBasePayload).getFirstRequest();
        byte[] req = scanBaseAttack.getRequest();
        byte[] scanBaseGrep = Utilities.helpers.stringToBytes(insertionPoint.calculateValue(scanBasePayload));

        int start = Utilities.helpers.indexOf(req, scanBaseGrep, true, 0, req.length);
        int end = start + scanBaseGrep.length;
        IScannerInsertionPoint valueInsertionPoint = new RawInsertionPoint(req, start, end);
        PayloadInjector valueInjector = new PayloadInjector(injector.getBase(), valueInsertionPoint);

        Attack randBase = valueInjector.probeAttack(Utilities.generateCanary());
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));

        String baseValue = "wrtqvetc";
        ArrayList<String> potentialValues = new ArrayList<>();
        potentialValues.add("1");
        potentialValues.add("false");
        // todo URL, domain, email, phone, postcode, any input validation that might block hitting the backend

        for (String potentialValue : potentialValues) {
            Attack potentialBase = valueInjector.probeAttack(potentialValue);

            if(!Utilities.similar(randBase, potentialBase)) {
                baseValue = potentialValue;
                break;
            }
        }

        Utilities.doActiveScan(Utilities.attemptRequest(injector.getService(), valueInsertionPoint.buildRequest(baseValue.getBytes())), valueInsertionPoint.getPayloadOffsets(baseValue.getBytes()));
    }

    private static boolean findPersistent(IHttpRequestResponse baseRequestResponse, Attack paramGuess, String attackID, CircularFifoQueue<String> recentParams, ArrayList<String> currentParams, HashSet<String> alreadyReported) {
        if (currentParams == null) {
            currentParams = new ArrayList<>();
        }

        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        if (failResp == null) {
            return false;
        }

        if (!Utilities.containsBytes(failResp, "wrtqva".getBytes())) {
            return false;
        }

        byte[] req = paramGuess.getFirstRequest().getRequest();

        for(Iterator<String> params = recentParams.iterator(); params.hasNext();) {
            String param = params.next();
            if(currentParams.contains(param) || alreadyReported.contains(param)) {
                continue;
            }

            byte[] canary = Utilities.helpers.stringToBytes(Utilities.toCanary(param.split("~", 2)[0]) + attackID);
            if (Utilities.containsBytes(failResp, canary) && !Utilities.containsBytes(req, canary)){
                Utilities.out("Identified persistent parameter on "+Utilities.getURL(baseRequestResponse) + ":" + param);
                params.remove();
                Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), paramGuess.getFirstRequest(), "Secret parameter", "Found persistent parameter: '"+param+"'. Disregard the request and look for " + Utilities.helpers.bytesToString(canary) + " in the response", "High", "Firm", "Investigate"));
                alreadyReported.add(param);
                return true;
            }
        }
        return false;
    }


//    static ArrayList<Attack> guessBackendParams(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
//
//        String baseValue = insertionPoint.getBaseValue();
//        PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);
//        String targetURL = baseRequestResponse.getHttpService().getHost();
//        Utilities.log("Initiating parameter name bruteforce on " + targetURL);
//
//        final String breaker = "=%3c%61%60%27%22%24%7b%7b%5c";
//        Attack base = injector.buildAttack(baseValue+"&"+Utilities.randomString(6)+ breaker, false);
//
//        for(int i=0; i<4; i++) {
//            base.addAttack(injector.buildAttack(baseValue+"&"+Utilities.randomString((i+1)*(i+1))+ breaker, false));
//        }
//
//        ArrayList<Attack> attacks = new ArrayList<>();
//        try {
//            for (int i = 0; i < Utilities.paramNames.size(); i++) { // i<Utilities.paramNames.size();
//                String candidate = Utilities.paramNames.get(i);
//                Attack paramGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
//                if (!Utilities.similar(base, paramGuess)) {
//                    Attack confirmParamGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
//                    base.addAttack(injector.buildAttack(baseValue + "&" + candidate + "z"+breaker, false));
//                    if (!Utilities.similar(base, confirmParamGuess)) {
//                        Probe validParam = new Probe("Backend param: " + candidate, 4, "&" + candidate + breaker, "&" + candidate + "=%3c%62%60%27%22%24%7b%7b%5c");
//                        validParam.setEscapeStrings("&" + Utilities.randomString(candidate.length()) + breaker, "&" + candidate + "z"+breaker);
//                        validParam.setRandomAnchor(false);
//                        ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
//                        if (!confirmed.isEmpty()) {
//                            Utilities.out("Identified backend parameter: " + candidate);
//                            attacks.addAll(confirmed);
//                        }
//                    } else {
//                        base.addAttack(paramGuess);
//                    }
//                }
//
//            }
//            Utilities.log("Parameter name bruteforce complete: "+targetURL);
//        }
//        catch (RuntimeException e) {
//            Utilities.log("Parameter name bruteforce aborted: "+targetURL);
//        }
//
//        return attacks;
//    }

}

class LengthCompare implements Comparator<String> {
    public int compare(String o1, String o2) {
        return Integer.compare(o1.length(), o2.length());
    }
}

