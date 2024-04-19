package burp;

import burp.albinowaxUtils.Attack;
import burp.model.header.HeaderMutationGuesser;
import burp.model.scanning.BulkScan;
import burp.model.utilities.Utilities;
import burp.view.ConfigurableSettings;
import burp.albinowaxUtils.CustomScanIssue;
import burp.albinowaxUtils.ParamInsertionPoint;
import burp.model.scanning.ParamScan;
import burp.albinowaxUtils.PayloadInjector;
import burp.albinowaxUtils.RawInsertionPoint;
import burp.model.scanning.Scan;
import org.apache.commons.collections4.queue.CircularFifoQueue;

import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

// todo: this was never used, why?
//class SimpleScan implements Runnable, IExtensionStateListener {
//
//    public void run() {
//
//    }
//
//    public void extensionUnloaded() {
//        utilities.log("Aborting param bruteforce");
//        utilities.unloaded.set(true);
//    }
//
//}

/**
 * Created by james on 30/08/2017.
 */
public class ParamGuesser implements Runnable {

    private IHttpRequestResponse req;
    private boolean backend;
    private byte type;
    private ThreadPoolExecutor taskEngine;
    private int stop;
    private ParamGrabber paramGrabber;
    private ParamAttack          attack;
    private ConfigurableSettings config;
    private       boolean   forceHttp1;
    private final Utilities utilities;
    private       byte[]    staticCanary;

    public ParamGuesser(
      IHttpRequestResponse req, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine,
      int stop, ConfigurableSettings config,
      Utilities utilities
    ) {
      this.paramGrabber = paramGrabber;
      this.req          = req;
      this.backend      = backend;
      this.type         = type;
      this.stop         = stop;
      this.taskEngine   = taskEngine;
      this.config       = config;
      this.utilities    = utilities;
      this.forceHttp1   = this.config.getBoolean("identify smuggle mutations") && this.type == Utilities.PARAM_HEADER;
      staticCanary      = config.getString("canary").getBytes();
    }

    ParamGuesser(ParamAttack attack, ThreadPoolExecutor taskEngine, ConfigurableSettings config, boolean forceHttp1,
                 Utilities utilities
    ) {
        this.attack = attack;
        this.req = attack.getBaseRequestResponse();
        this.taskEngine = taskEngine;
        this.config = config;
        this.forceHttp1 = forceHttp1;
        staticCanary = config.getString("canary").getBytes();
        this.utilities = utilities;
    }

    public void run() {
        try {
            if (this.attack == null) {
                if (req.getResponse() == null) {
                    utilities.log("Baserequest has no response - fetching...");
                    try {
                        req = utilities.callbacks.makeHttpRequest(req.getHttpService(), req.getRequest(), this.forceHttp1);
                    } catch (RuntimeException e) {
                        utilities.out("Aborting attack due to failed lookup");
                        return;
                    }
                    if (req == null) {
                        utilities.out("Aborting attack due to null response");
                        return;
                    }
                }
                this.attack = new ParamAttack(req, type, paramGrabber, stop, config, utilities);
            }

            // Check for mutations
            if (this.type == Utilities.PARAM_HEADER && config.getBoolean("identify smuggle mutations")) {
                HeaderMutationGuesser mutationGuesser = new HeaderMutationGuesser(req, this.config, utilities);
                ArrayList<String>     mutations       = mutationGuesser.guessMutations();
                this.attack.setHeaderMutations(mutations);

                // Report if required
                if (mutations != null) {
                    mutationGuesser.reportMutations(mutations);
                }
            }

            ArrayList<Attack> paramGuesses = guessParams(attack);
            if (!paramGuesses.isEmpty()) {
                utilities.callbacks.addScanIssue(utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req, "", ""));
            }
        } catch (Exception e) {
            utilities.out("Attack aborted by exception");
            utilities.showError(e);
            throw e;
        }

//        if(backend) {
//            IRequestInfo info = utilities.helpers.analyzeRequest(req);
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
//                        utilities.callbacks.addScanIssue(utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req));
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
        final IHttpService    service  = baseRequestResponse.getHttpService();
        final PayloadInjector injector = state.getInjector();
        final String          attackID = state.getAttackID();
        final String targetURL = state.getTargetURL();
        final boolean                 tryMethodFlip  = state.shouldTryMethodFlip();
        final ParamInsertionPoint     insertionPoint = state.getInsertionPoint();
        final HashMap<String, String> requestParams  = state.getRequestParams();
        final WordProvider bonusParams = state.getBonusParams();
        final byte type = state.type;
        ArrayList<String> headerMutations = state.getHeaderMutations();

        ArrayList<Attack> attacks = new ArrayList<>();
        int completedAttacks = 0;
        int start = 0; // todo could manually set this
        int stop = state.getStop();
        Attack base = state.getBase();
        byte[] invertedBase = state.getInvertedBase();
        Attack altBase = state.getAltBase();
        ParamHolder paramBuckets = state.getParamBuckets();

        if (utilities.globalSettings.getBoolean("carpet bomb")) {
            utilities.out("Warning: carpet bomb mode is on, so no parameters will be detected.");
        }

        if (!state.started) {
            utilities.out("Initiating "+utilities.getNameFromType(type)+" bruteforce on "+ targetURL);
            state.started = true;
        }
        else {
            utilities.out("Resuming "+utilities.getNameFromType(type)+" bruteforce at "+state.seed+" on "+ targetURL);
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
                } else {
                    if (!config.getBoolean("bruteforce")) {
                        utilities.out("Completed attack on " + targetURL);
                        if (taskEngine != null) {
                            utilities.out("Completed " + (taskEngine.getCompletedTaskCount() + 1) + "/" + (taskEngine.getTaskCount()));
                        }
                        return attacks;
                    }
                    state.seed = utilities.generate(state.seed, bucketSize, newParams);
                }
                newParams.removeAll(state.alreadyReported);
                paramBuckets.addParams(newParams, true);
            }

            ArrayList<String> candidates;
            try {
                candidates = paramBuckets.pop();
                Iterator<String> iterator = candidates.iterator();
            } catch (NoSuchElementException e) {
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
            if (headerMutations == null) {
                headerMutations = new ArrayList<String>();
            }

            // Ensure that the identity mutation is scanned
            if (headerMutations.size() == 0 || headerMutations.get(0) != null) {
                headerMutations.add(0, null);
            }
            Iterator<String> iterator = headerMutations.iterator();
            while (iterator.hasNext()) {
                String mutation = iterator.next();
                Attack paramGuess = injector.probeAttack(submission, mutation);

                if (!candidates.contains("~")) {
                    if (findPersistent(baseRequestResponse, paramGuess, attackID, state.recentParams, candidates, state.alreadyReported)) {
                        state.updateBaseline();
                    }
                    state.recentParams.addAll(candidates); // fixme this results in params being found multiple times
                }

                Attack localBase;
                if (submission.contains("~")) {
                    localBase = new Attack(utilities);
                    localBase.addAttack(base);
                } else {
                    localBase = base;
                }

                if (!utilities.globalSettings.getBoolean("carpet bomb") && !utilities.similar(localBase, paramGuess)) {
                    Attack confirmParamGuess = injector.probeAttack(submission, mutation);

                    Attack failAttack = injector.probeAttack(Keysmith.permute(submission), mutation);

                    // this to prevent error messages obscuring persistent inputs
                    findPersistent(baseRequestResponse, failAttack, attackID, state.recentParams, null, state.alreadyReported);
                    localBase.addAttack(failAttack);

                    if (!utilities.similar(localBase, confirmParamGuess)) {
                        if (candidates.size() > 1) {
                            utilities.log("Splitting " + submission);
                            ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                            utilities.log("Got " + String.join("|", left));
                            ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2, candidates.size()));
                            utilities.log("Got " + String.join("|", right));
                            paramBuckets.push(left);
                            paramBuckets.push(right);
                        } else {
                            if (state.alreadyReported.contains(submission)) {
                                utilities.out("Ignoring reporting of submission " + submission + " using mutation " + mutation + " as already reported.");
                                continue;
                            }

                            Attack WAFCatcher = new Attack(utilities.attemptRequest(service, utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-header", submission), this.forceHttp1), utilities);
                            WAFCatcher.addAttack(new Attack(utilities.attemptRequest(service, utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-head", submission), this.forceHttp1), utilities));
                            if (!utilities.similar(WAFCatcher, confirmParamGuess)) {
                                Probe validParam = new Probe("Found unlinked param: " + submission, 4, submission);
                                validParam.setEscapeStrings(Keysmith.permute(submission), Keysmith.permute(submission, false));
                                validParam.setRandomAnchor(false);
                                validParam.setPrefix(Probe.REPLACE);
                                ArrayList<Attack> confirmed = injector.fuzz(localBase, validParam, mutation);
                                if (!confirmed.isEmpty()) {
                                    state.alreadyReported.add(submission);
                                    Utilities.reportedParams.add(submission);
                                    utilities.out("Identified parameter on " + targetURL + ": " + submission);

                                    boolean cacheSuccess = false;
                                    if (type == Utilities.PARAM_HEADER || type == IParameter.PARAM_COOKIE) {
                                        cacheSuccess = cachePoison(injector, submission, failAttack.getFirstRequest());
                                    }
                                    if (!utilities.globalSettings.getBoolean("poison only")) {
                                        String title = "Secret input: " + utilities.getNameFromType(type);
                                        if (!cacheSuccess && canSeeCache(paramGuess.getFirstRequest().getResponse())) {
                                            title = "Secret uncached input: " + utilities.getNameFromType(type);
                                        }
                                        if (utilities.globalSettings.getBoolean("name in issue")) {
                                            title += ": " + submission.split("~")[0];
                                        }
                                        utilities.callbacks.addScanIssue(utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), baseRequestResponse, title, "Unlinked parameter identified."));
                                        if (type != Utilities.PARAM_HEADER || utilities.containsBytes(paramGuess.getFirstRequest().getResponse(), staticCanary)) {
                                            scanParam(insertionPoint, injector, submission.split("~", 2)[0]);
                                        }

                                        base = state.updateBaseline();
                                    }

                                    //utilities.callbacks.doPassiveScan(service.getHost(), service.getPort(), service.getProtocol().equals("https"), paramGuess.getFirstRequest().getRequest(), paramGuess.getFirstRequest().getResponse());

                                    if (config.getBoolean("dynamic keyload")) {
                                        ArrayList<String> newWords = new ArrayList<>(Keysmith.getWords(utilities.helpers.bytesToString(paramGuess.getFirstRequest().getResponse())));
                                        addNewKeys(newWords, state, bucketSize, paramBuckets, candidates, paramGuess);
                                    }
                                } else {
                                    utilities.out(targetURL + " questionable parameter: " + candidates);
                                }
                            }
                        }
                    } else{
                        utilities.log(targetURL + " couldn't replicate: " + candidates);
                        base.addAttack(paramGuess);
                    }

                    if (config.getBoolean("dynamic keyload")) {
                        addNewKeys(Keysmith.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams,
                          utilities
                        ), state, bucketSize, paramBuckets, candidates, paramGuess);
                    }

                } else if (tryMethodFlip) {
                    Attack paramGrab = new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase), utilities);
                    findPersistent(baseRequestResponse, paramGrab, attackID, state.recentParams, null, state.alreadyReported);

                    if (!utilities.similar(altBase, paramGrab)) {
                        utilities.log("Potential GETbase param: " + candidates);
                        injector.probeAttack(Keysmith.permute(submission), mutation);
                        altBase.addAttack(new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase), utilities));
                        injector.probeAttack(submission, mutation);

                        paramGrab = new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase, this.forceHttp1), utilities);
                        if (!utilities.similar(altBase, paramGrab)) {

                            if (candidates.size() > 1) {
                                utilities.log("Splitting " + submission);
                                ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                                ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2 + 1, candidates.size()));
                                paramBuckets.push(left);
                                paramBuckets.push(right);
                            } else {
                                utilities.out("Confirmed GETbase param: " + candidates);
                                IHttpRequestResponse[] evidence = new IHttpRequestResponse[3];
                                evidence[0] = altBase.getFirstRequest();
                                evidence[1] = paramGuess.getFirstRequest();
                                evidence[2] = paramGrab.getFirstRequest();
                                utilities.callbacks.addScanIssue(new CustomScanIssue(service, utilities.getURL(baseRequestResponse), evidence, "Secret parameter", "Parameter name: '" + candidates + "'. Review the three requests attached in chronological order.", "Medium", "Tentative", "Investigate"));

                                altBase = new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase, this.forceHttp1), utilities);
                                altBase.addAttack(new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase, this.forceHttp1), utilities));
                                altBase.addAttack(new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase, this.forceHttp1), utilities));
                                altBase.addAttack(new Attack(utilities.callbacks.makeHttpRequest(service, invertedBase, this.forceHttp1), utilities));
                            }
                        }
                    }
                }
            }
        }


        state.incrStop();
        taskEngine.execute(new ParamGuesser(state, taskEngine, config, this.forceHttp1, utilities));

        return attacks;
    }



    private boolean cachePoison(PayloadInjector injector, String param, IHttpRequestResponse baseResponse) {
        if (!utilities.globalSettings.getBoolean("try cache poison")) {
            return false;
        }

        try {
            IHttpRequestResponse base = injector.getBase();
            PayloadInjector altInject = new PayloadInjector(base, new ParamNameInsertionPoint(base.getRequest(), "guesser", "", IParameter.PARAM_URL, "repliblah", utilities), utilities);
            Probe validParam = new Probe("Potentially swappable param: " + param, 5, param);
            validParam.setEscapeStrings(Keysmith.permute(param), Keysmith.permute(param, false));
            validParam.setRandomAnchor(false);
            validParam.setPrefix(Probe.REPLACE);
            Attack paramBase = new Attack(utilities);
            paramBase.addAttack(altInject.probeAttack(Utilities.generateCanary()));
            paramBase.addAttack(altInject.probeAttack(Utilities.generateCanary()));
            ArrayList<Attack> confirmed = altInject.fuzz(paramBase, validParam);
            if (!confirmed.isEmpty()) {
                utilities.callbacks.addScanIssue(utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), base, "Potentially swappable param", ""));
            }

            byte[] testReq = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(param));
            testReq = utilities.addCacheBuster(testReq, utilities.generateCanary());

            int attackDedication;
            if (canSeeCache(base.getResponse())) {
                attackDedication = 10;
            }
            else {
                attackDedication = 5;
                for (int i=0;i<5;i++) {
                    IHttpRequestResponse base2 = utilities.attemptRequest(injector.getService(), testReq);
                    if (canSeeCache(base2.getResponse())) {
                        attackDedication = 30;
                        break;
                    }
                }
            }




            String pathCacheBuster = utilities.generateCanary() + ".jpg";

            //String path = utilities.getPathFromRequest(base.getRequest());
            //byte[] base404 = utilities.replaceFirst(base.getRequest(), path.getBytes(), (path+pathCacheBuster).getBytes());
            byte[] base404 = utilities.appendToPath(base.getRequest(), pathCacheBuster);


            IHttpRequestResponse get404 = utilities.attemptRequest(injector.getService(), base404);
            short get404Code = utilities.helpers.analyzeResponse(get404.getResponse()).getStatusCode();


            IHttpRequestResponse testResp = utilities.attemptRequest(injector.getService(), testReq);

            boolean reflectPoisonMightWork = utilities.containsBytes(testResp.getResponse(), staticCanary);
            boolean statusPoisonMightWork = utilities.helpers.analyzeResponse(baseResponse.getResponse()).getStatusCode() != utilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode();


            ArrayList<String> suffixes = new ArrayList<>();
            ArrayList<String> suffixesWhich404 = new ArrayList<>();
            String[] potentialSuffixes = new String[]{"index.php/zxcvk.jpg", "zxcvk.jpg"};

            suffixes.add("");
            if (reflectPoisonMightWork) {
                for (String suffix : potentialSuffixes) {
                    testResp = utilities.attemptRequest(injector.getService(), utilities.appendToPath(testReq, suffix));
                    if (utilities.containsBytes(testResp.getResponse(), staticCanary)) {
                        if (utilities.helpers.analyzeResponse(testResp.getResponse()).getStatusCode() == 200) {
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

            utilities.log("Dedicated: "+attackDedication);
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

                if (!reflectPoisonMightWork && !statusPoisonMightWork && utilities.globalSettings.getBoolean("twitchy cache poison")) {
                    if (tryDiffCache(injector, param, attackDedication)) {
                        return true;
                    }
                }
            }

            utilities.log("Failed cache poisoning check");
        }
        catch (java.lang.Exception e) {
            utilities.err(e.getMessage()+"\n\n"+e.getStackTrace()[0]);
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
        String canary = utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(param));
        setPoison200Req = utilities.appendToPath(setPoison200Req, canary);
        for(int j=0; j<attackDedication; j++) {
            utilities.attemptRequest(injector.getService(), setPoison200Req);
        }

        byte[] getPoisonReq = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes("z"+param+"z"));

        IHttpRequestResponse getPoisoned = utilities.attemptRequest(injector.getService(), utilities.appendToPath(getPoisonReq, canary));

        IResponseVariations baseline = utilities.helpers.analyzeResponseVariations();
        IResponseVariations poisoned = utilities.helpers.analyzeResponseVariations(getPoisoned.getResponse());
        IHttpRequestResponse resp = null;
        boolean diff = false;
        HashSet<String> diffed = new HashSet<>();
        for(int i=0; i<10; i++) {
            diffed.clear();
            diff = false;
            byte[] fakePoisonReq =  utilities.appendToPath(getPoisonReq, utilities.generateCanary()+".jpg");
            resp = utilities.attemptRequest(injector.getService(), fakePoisonReq);
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
            utilities.callbacks.addScanIssue(new CustomScanIssue(getPoisoned.getHttpService(), utilities.getURL(getPoisoned), attachedRequests, "Attribute-diff cache poisoning: "+param, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming "+diffed, "High", "Tentative", "Investigate"));
            return true;
        }

        return false;
    }

    private boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, short get404Code) {
        String canary = utilities.generateCanary()+".jpg";
        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(addStatusPayload(param)));
        setPoison200Req = utilities.appendToPath(setPoison200Req, canary);

        byte[] getPoison200Req = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(addStatusPayload("xyz"+param+"z")));
        getPoison200Req = utilities.appendToPath(getPoison200Req, canary);

        for(int j=0; j<attackDedication; j++) {
            utilities.attemptRequest(injector.getService(), setPoison200Req);
        }

        for(int j=0; j<attackDedication; j+=3) {
            IHttpRequestResponse getPoison200 = utilities.attemptRequest(injector.getService(), getPoison200Req);
            short getPoison200Code = utilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
            if (getPoison200Code != get404Code) {
                utilities.callbacks.addScanIssue(
                  new CustomScanIssue(
                    getPoison200.getHttpService(),
                    utilities.getURL(getPoison200),
                    new IHttpRequestResponse[] {getPoison200}, "Status-code cache poisoning " + j,
                    "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming",
                    "High", "Tentative",
                    "Investigate"));
            }
            return true;
        }

        return false;
    }

//    private boolean tryStatusCache(PayloadInjector injector, String param, int attackDedication, String pathCacheBuster, byte[] base404, short get404Code, int i) {
//        IParameter cacheBuster = utilities.helpers.buildParameter(utilities.generateCanary(), "1", IParameter.PARAM_URL);
//
//        byte[] setPoison200Req = injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(addStatusPayload(param)));
//        setPoison200Req = utilities.appendToPath(setPoison200Req, pathCacheBuster);
//
//        for(int j=attackDedication-i; j<attackDedication; j++) {
//            utilities.attemptRequest(injector.getService(), utilities.helpers.addParameter(setPoison200Req, cacheBuster));
//        }
//
//        for(int j=attackDedication-i; j<attackDedication; j+=3) {
//            IHttpRequestResponse getPoison200 = utilities.attemptRequest(injector.getService(), utilities.helpers.addParameter(base404, cacheBuster));
//            short getPoison200Code = utilities.helpers.analyzeResponse(getPoison200.getResponse()).getStatusCode();
//
//            if (getPoison200Code != get404Code) {
//                utilities.log("Successful cache poisoning check");
//                utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison200.getHttpService(), utilities.getURL(getPoison200), getPoison200, "Dubious cache poisoning "+i, "Cache poisoning: '" + param + "'. Diff based cache poisoning. Good luck confirming", "High", "Tentative", "Investigate"));
//                return true;
//            }
//        }
//        return false;
//    }

    private boolean tryReflectCache(PayloadInjector injector, String param, IHttpRequestResponse base, int attackDedication, int i, String pathSuffix) {
        IHttpService service = injector.getService();
        byte[] setPoisonReq = utilities.appendToPath(injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(param)), pathSuffix);

        String cacheBuster = utilities.generateCanary();
        setPoisonReq = utilities.addCacheBuster(setPoisonReq, cacheBuster);
        for (int j = attackDedication - i; j < attackDedication; j++) {
            utilities.attemptRequest(service, setPoisonReq);
        }

        for (int j = attackDedication - i; j < attackDedication; j += 3) {
            IHttpRequestResponse getPoison = utilities.attemptRequest(service, utilities.appendToPath(utilities.addCacheBuster(base.getRequest(), cacheBuster), pathSuffix));
            if (utilities.containsBytes(getPoison.getResponse(), staticCanary)) {
                utilities.log("Successful cache poisoning check");
                String title = "Cache poisoning";

                byte[] headerSplitReq = utilities.appendToPath(injector.getInsertionPoint().buildRequest(utilities.helpers.stringToBytes(param + "~zxcv\rvcz")), pathSuffix);
                cacheBuster = utilities.generateCanary();
                byte[] headerSplitResp = utilities.attemptRequest(service, utilities.addCacheBuster(headerSplitReq, cacheBuster)).getResponse();
                if (utilities.containsBytes(Arrays.copyOfRange(headerSplitResp, 0, utilities.getBodyStart(headerSplitReq)), "zxcv\rvcz".getBytes())) {
                    title = "Severe cache poisoning";
                }

                title = title + " "+i;
                utilities.callbacks.addScanIssue(new CustomScanIssue(getPoison.getHttpService(), utilities.getURL(getPoison),
                  new IHttpRequestResponse[] {getPoison}, title, "Cache poisoning: '" + param + "'. Disregard the request and look for "+config.getString("canary")+" in the response", "High", "Firm", "Investigate"));
                return true;
            }
        }
        return false;
    }


    private boolean canSeeCache(byte[] response) {
        if (response == null) {
            return false;
        }
        String[] headers = new String[]{"Age", "X-Cache", "Cache", "X-Cache-Hits", "X-Varnish-Cache", "X-Drupal-Cache", "X-Varnish", "CF-Cache-Status", "CF-RAY"};
        for(String header: headers) {
            if(utilities.getHeaderOffsets(response, header) != null) {
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
                utilities.log("Found new key: " + key);
                state.valueParams.add(key);
                discoveredParams.add(key); // fixme probably adds the key in the wrong format
                paramGrabber.saveParams(paramGuess.getFirstRequest());
            }
        }

        paramBuckets.addParams(discoveredParams, true);
    }

    private void scanParam(ParamInsertionPoint insertionPoint, PayloadInjector injector, String scanBasePayload) {

        try {
            IHttpRequestResponse scanBaseAttack = injector.probeAttack(scanBasePayload).getFirstRequest();
            byte[] req = scanBaseAttack.getRequest();
            byte[] scanBaseGrep = utilities.helpers.stringToBytes(insertionPoint.calculateValue(scanBasePayload));

            int start = utilities.helpers.indexOf(req, scanBaseGrep, true, 0, req.length);
            int end = start + scanBaseGrep.length;

            // todo test this
            // todo make separate option for core scan vs param scan
            ArrayList<int[]> offsets = new ArrayList<>();
            offsets.add(new int[]{start, end});
            IHttpService service = scanBaseAttack.getHttpService();

            if (utilities.globalSettings.getBoolean("probe identified params") && insertionPoint.type != Utilities.PARAM_HEADER) {
                IScannerInsertionPoint valueInsertionPoint = new RawInsertionPoint(req, scanBasePayload, start, end);
              
                  for(Scan scan : BulkScan.scans) {
                    if (scan instanceof ParamScan) {
                        ((ParamScan) scan).doActiveScan(scanBaseAttack, valueInsertionPoint);
                    }
                }
            }

            if (!utilities.globalSettings.getBoolean("scan identified params")) {
                return;
            }

            if (!utilities.isBurpPro()) {
                utilities.out("Can't autoscan identified parameter - requires pro edition");
                return;
            }

            utilities.callbacks.doActiveScan(service.getHost(), service.getPort(), utilities.isHTTPS(service), req, offsets);
            //ValueGuesser.guessValue(scanBaseAttack, start, end);

        } catch (Exception e) {
            // don't let a broken scan take out the param-miner thread
            utilities.showError(e);
        }
    }

    private boolean findPersistent(IHttpRequestResponse baseRequestResponse, Attack paramGuess, String attackID, CircularFifoQueue<String> recentParams, ArrayList<String> currentParams, HashSet<String> alreadyReported) {
        if (currentParams == null) {
            currentParams = new ArrayList<>();
        }

        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        if (failResp == null) {
            return false;
        }

        if (!utilities.containsBytes(failResp, staticCanary)) {
            return false;
        }

        byte[] req = paramGuess.getFirstRequest().getRequest();

        for(Iterator<String> params = recentParams.iterator(); params.hasNext();) {
            String param = params.next();
            if(currentParams.contains(param) || alreadyReported.contains(param)) {
                continue;
            }

            byte[] canary = utilities.helpers.stringToBytes(utilities.toCanary(param.split("~", 2)[0]) + attackID);
            if (utilities.containsBytes(failResp, canary) && !utilities.containsBytes(req, canary)){
                utilities.out("Identified persistent parameter on "+utilities.getURL(baseRequestResponse) + ":" + param);
                params.remove();
                utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), utilities.getURL(baseRequestResponse),
                  new IHttpRequestResponse[] {paramGuess.getFirstRequest()}, "Secret parameter", "Found persistent parameter: '"+param+"'. Disregard the request and look for " + utilities.helpers.bytesToString(canary) + " in the response", "High", "Firm", "Investigate"));
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
//        utilities.log("Initiating parameter name bruteforce on " + targetURL);
//
//        final String breaker = "=%3c%61%60%27%22%24%7b%7b%5c";
//        Attack base = injector.buildAttack(baseValue+"&"+utilities.randomString(6)+ breaker, false);
//
//        for(int i=0; i<4; i++) {
//            base.addAttack(injector.buildAttack(baseValue+"&"+utilities.randomString((i+1)*(i+1))+ breaker, false));
//        }
//
//        ArrayList<Attack> attacks = new ArrayList<>();
//        try {
//            for (int i = 0; i < utilities.paramNames.size(); i++) { // i<utilities.paramNames.size();
//                String candidate = utilities.paramNames.get(i);
//                Attack paramGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
//                if (!utilities.similar(base, paramGuess)) {
//                    Attack confirmParamGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
//                    base.addAttack(injector.buildAttack(baseValue + "&" + candidate + "z"+breaker, false));
//                    if (!utilities.similar(base, confirmParamGuess)) {
//                        Probe validParam = new Probe("Backend param: " + candidate, 4, "&" + candidate + breaker, "&" + candidate + "=%3c%62%60%27%22%24%7b%7b%5c");
//                        validParam.setEscapeStrings("&" + utilities.randomString(candidate.length()) + breaker, "&" + candidate + "z"+breaker);
//                        validParam.setRandomAnchor(false);
//                        ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
//                        if (!confirmed.isEmpty()) {
//                            utilities.out("Identified backend parameter: " + candidate);
//                            attacks.addAll(confirmed);
//                        }
//                    } else {
//                        base.addAttack(paramGuess);
//                    }
//                }
//
//            }
//            utilities.log("Parameter name bruteforce complete: "+targetURL);
//        }
//        catch (RuntimeException e) {
//            utilities.log("Parameter name bruteforce aborted: "+targetURL);
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

