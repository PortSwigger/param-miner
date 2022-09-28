package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

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
    private boolean forceHttp1;

    private byte[] staticCanary;

    ParamGuesser(IHttpRequestResponse req, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine, int stop, ConfigurableSettings config) {
        this.paramGrabber = paramGrabber;
        this.req = req;
        this.backend = backend;
        this.type = type;
        this.stop = stop;
        this.taskEngine = taskEngine;
        this.config = config;
        this.forceHttp1 = this.config.getBoolean("identify smuggle mutations") && this.type == Utilities.PARAM_HEADER;
        staticCanary = config.getString("canary").getBytes();
    }

    ParamGuesser(ParamAttack attack, ThreadPoolExecutor taskEngine, ConfigurableSettings config, boolean forceHttp1) {
        this.attack = attack;
        this.req = attack.getBaseRequestResponse();
        this.taskEngine = taskEngine;
        this.config = config;
        this.forceHttp1 = forceHttp1;
        staticCanary = config.getString("canary").getBytes();
    }

    public void run() {
        try {
            if (this.attack == null) {
                if (req.getResponse() == null) {
                    Utilities.log("Baserequest has no response - fetching...");
                    try {
                        req = Scan.request(req.getHttpService(), req.getRequest(), 0, this.forceHttp1);
                    } catch (RuntimeException e) {
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

            // Check for mutations
            if (this.type == Utilities.PARAM_HEADER && config.getBoolean("identify smuggle mutations")) {
                HeaderMutationGuesser mutationGuesser = new HeaderMutationGuesser(req, this.config);
                ArrayList<String> mutations = mutationGuesser.guessMutations();
                this.attack.setHeaderMutations(mutations);

                // Report if required
                if (mutations != null) {
                    mutationGuesser.reportMutations(mutations);
                }
            }

            ArrayList<Attack> paramGuesses = guessParams(attack);
            if (!paramGuesses.isEmpty()) {
                Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req, "", ""));
            }
        } catch (Exception e) {
            Utilities.out("Attack aborted by exception");
            Utilities.showError(e);
            throw e;
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
        final HashMap<String, String> requestParams = state.getRequestParams();
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

        if (Utilities.globalSettings.getBoolean("carpet bomb")) {
            Utilities.out("Warning: carpet bomb mode is on, so no parameters will be detected.");
        }

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
                } else {
                    if (!config.getBoolean("bruteforce")) {
                        Utilities.out("Completed attack on " + targetURL);
                        if (taskEngine != null) {
                            Utilities.out("Completed " + (taskEngine.getCompletedTaskCount() + 1) + "/" + (taskEngine.getTaskCount()));
                        }
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
                    localBase = new Attack();
                    localBase.addAttack(base);
                } else {
                    localBase = base;
                }

                if (!Utilities.globalSettings.getBoolean("carpet bomb") && !Utilities.similar(localBase, paramGuess)) {
                    Attack confirmParamGuess = injector.probeAttack(submission, mutation);

                    Attack failAttack = injector.probeAttack(Keysmith.permute(submission), mutation);

                    // this to prevent error messages obscuring persistent inputs
                    findPersistent(baseRequestResponse, failAttack, attackID, state.recentParams, null, state.alreadyReported);
                    localBase.addAttack(failAttack);

                    if (!Utilities.similar(localBase, confirmParamGuess)) {
                        if (candidates.size() > 1) {
                            Utilities.log("Splitting " + submission);
                            ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                            Utilities.log("Got " + String.join("|", left));
                            ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2, candidates.size()));
                            Utilities.log("Got " + String.join("|", right));
                            paramBuckets.push(left);
                            paramBuckets.push(right);
                        } else {
                            if (state.alreadyReported.contains(submission)) {
                                Utilities.out("Ignoring reporting of submission " + submission + " using mutation " + mutation + " as already reported.");
                                continue;
                            }

                            Attack WAFCatcher = new Attack(Scan.request(service, Utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-header", submission), 0, this.forceHttp1));
                            WAFCatcher.addAttack(new Attack(Scan.request(service, Utilities.addOrReplaceHeader(baseRequestResponse.getRequest(), "junk-head", submission), 0, this.forceHttp1)));
                            if (!Utilities.similar(WAFCatcher, confirmParamGuess)) {
                                Probe validParam = new Probe("Found unlinked param: " + submission, 4, submission);
                                validParam.setEscapeStrings(Keysmith.permute(submission), Keysmith.permute(submission, false));
                                validParam.setRandomAnchor(false);
                                validParam.setPrefix(Probe.REPLACE);
                                ArrayList<Attack> confirmed = injector.fuzz(localBase, validParam, mutation);
                                if (!confirmed.isEmpty()) {
                                    state.alreadyReported.add(submission);
                                    Utilities.reportedParams.add(submission);
                                    Utilities.out("Identified parameter on " + targetURL + ": " + submission);

                                    DiscoveredParam discoveredParam = new DiscoveredParam(confirmed, injector, submission, failAttack, paramGuess, baseRequestResponse);
                                    discoveredParam.report();
                                    base = state.updateBaseline();

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
                    } else{
                        Utilities.log(targetURL + " couldn't replicate: " + candidates);
                        base.addAttack(paramGuess);
                    }

                    if (config.getBoolean("dynamic keyload")) {
                        addNewKeys(Keysmith.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams), state, bucketSize, paramBuckets, candidates, paramGuess);
                    }

                } else if (tryMethodFlip) {
                    Attack paramGrab = new Attack(Scan.request(service, invertedBase));
                    findPersistent(baseRequestResponse, paramGrab, attackID, state.recentParams, null, state.alreadyReported);

                    if (!Utilities.similar(altBase, paramGrab)) {
                        Utilities.log("Potential GETbase param: " + candidates);
                        injector.probeAttack(Keysmith.permute(submission), mutation);
                        altBase.addAttack(new Attack(Scan.request(service, invertedBase)));
                        injector.probeAttack(submission, mutation);

                        paramGrab = new Attack(Scan.request(service, invertedBase, 0, this.forceHttp1));
                        if (!Utilities.similar(altBase, paramGrab)) {

                            if (candidates.size() > 1) {
                                Utilities.log("Splitting " + submission);
                                ArrayList<String> left = new ArrayList<>(candidates.subList(0, candidates.size() / 2));
                                ArrayList<String> right = new ArrayList<>(candidates.subList(candidates.size() / 2 + 1, candidates.size()));
                                paramBuckets.push(left);
                                paramBuckets.push(right);
                            } else {
                                Utilities.out("Confirmed GETbase param: " + candidates);
                                IHttpRequestResponse[] evidence = new IHttpRequestResponse[3];
                                evidence[0] = altBase.getFirstRequest();
                                evidence[1] = paramGuess.getFirstRequest();
                                evidence[2] = paramGrab.getFirstRequest();
                                Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(baseRequestResponse), evidence, "Secret parameter", "Parameter name: '" + candidates + "'. Review the three requests attached in chronological order.", "Medium", "Tentative", "Investigate"));

                                altBase = new Attack(Scan.request(service, invertedBase, 0, this.forceHttp1));
                                altBase.addAttack(new Attack(Scan.request(service, invertedBase, 0, this.forceHttp1)));
                                altBase.addAttack(new Attack(Scan.request(service, invertedBase, 0, this.forceHttp1)));
                                altBase.addAttack(new Attack(Scan.request(service, invertedBase, 0, this.forceHttp1)));
                            }
                        }
                    }
                }
            }
        }


        state.incrStop();
        taskEngine.execute(new ParamGuesser(state, taskEngine, config, this.forceHttp1));

        return attacks;
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

    private boolean findPersistent(IHttpRequestResponse baseRequestResponse, Attack paramGuess, String attackID, CircularFifoQueue<String> recentParams, ArrayList<String> currentParams, HashSet<String> alreadyReported) {
        if (currentParams == null) {
            currentParams = new ArrayList<>();
        }

        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        if (failResp == null) {
            return false;
        }

        if (!Utilities.containsBytes(failResp, staticCanary)) {
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

