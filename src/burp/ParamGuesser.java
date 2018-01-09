package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import static java.lang.Math.max;
import static java.lang.Math.min;


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
class ParamGuesser implements Runnable, IExtensionStateListener {

    private IHttpRequestResponse req;
    private boolean backend;
    private byte type;
    private ThreadPoolExecutor taskEngine;
    private int stop;
    private ParamGrabber paramGrabber;
    private ParamAttack attack;

    ParamGuesser(IHttpRequestResponse req, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine, int stop) {
        this.paramGrabber = paramGrabber;
        this.req = req;
        this.backend = backend;
        this.type = type;
        this.stop = stop;
        this.taskEngine = taskEngine;
    }

    ParamGuesser(ParamAttack attack, ThreadPoolExecutor taskEngine) {
        this.attack = attack;
        this.req = attack.getBaseRequestResponse();
        this.taskEngine = taskEngine;
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
            this.attack = new ParamAttack(req, type, paramGrabber, stop);
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

    public void extensionUnloaded() {
        Utilities.log("Aborting param bruteforce");
        Utilities.unloaded.set(true);
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
            Utilities.out("Initiating "+Utilities.getNameFromType(type)+" bruteforce of "+paramBuckets.size()+" on "+ targetURL);
            state.started = true;
        }
        else {
            Utilities.out("Resuming "+Utilities.getNameFromType(type)+" bruteforce at "+paramBuckets.size()+"/"+state.seed+" on "+ targetURL);
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
                            if(completedAttacks > start) {
                                if (Utilities.LIGHTWEIGHT) {
                                    Utilities.out("Completed attack on "+ targetURL);
                                    return attacks;
                                }
                                else {
                                    Utilities.out("Switching to bruteforce mode after this attack");
                                }
                            }
                            break;
                        }
                        newParams.add(next);
                    }
                }
                else {
                    state.seed = Utilities.generate(state.seed, bucketSize, newParams);
                }
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

            candidates.removeAll(state.alreadyReported);
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

            if (!Utilities.similar(localBase, paramGuess)) {
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

                        Probe validParam = new Probe("Found unlinked param: " + submission, 4, submission);
                        validParam.setEscapeStrings(Keysmith.permute(submission), Keysmith.permute(submission, false));
                        validParam.setRandomAnchor(false);
                        validParam.setPrefix(Probe.REPLACE);
                        ArrayList<Attack> confirmed = injector.fuzz(localBase, validParam);
                        if (!confirmed.isEmpty()) {
                            state.alreadyReported.add(submission);
                            Utilities.out(targetURL + " identified parameter: " + candidates);
                            Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), baseRequestResponse, "Secret input: "+Utilities.getNameFromType(type)));
                            //scanParam(insertionPoint, injector, submission.split("~", 2)[0]);
                            if (type == Utilities.PARAM_HEADER || type == IParameter.PARAM_COOKIE) {
                                cachePoison(injector, submission);
                            }
                            //Utilities.callbacks.doPassiveScan(service.getHost(), service.getPort(), service.getProtocol().equals("https"), paramGuess.getFirstRequest().getRequest(), paramGuess.getFirstRequest().getResponse());
                            base = state.updateBaseline();
                            ArrayList<String> newWords = new ArrayList<String>(Keysmith.getWords(Utilities.helpers.bytesToString(paramGuess.getFirstRequest().getResponse())));
                            //addNewKeys(newWords, state, bucketSize, paramBuckets, candidates, paramGuess);
                        } else {
                            Utilities.out(targetURL + " questionable parameter: " + candidates);
                        }
                    }
                } else {
                    Utilities.log(targetURL + " couldn't replicate: " + candidates);
                    base.addAttack(paramGuess);
                }

                addNewKeys(Keysmith.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams), state, bucketSize, paramBuckets, candidates, paramGuess);

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


        Utilities.log("Parameter name bruteforce complete: "+targetURL);
        taskEngine.execute(new ParamGuesser(state, taskEngine));

        return attacks;
    }

    private IHttpRequestResponse cachePoison(PayloadInjector injector, String param) {
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
        if(!confirmed.isEmpty()) {
            Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), base, "Potentially swappable param"));
        }


        byte[] request = injector.getInsertionPoint().buildRequest(param.getBytes());
        IParameter cacheBuster = Utilities.helpers.buildParameter(Utilities.generateCanary(), "1", IParameter.PARAM_URL);
        request = Utilities.helpers.addParameter(request, cacheBuster);
        if(Utilities.containsBytes(Utilities.attemptRequest(injector.getService(), request).getResponse(), "wrtqv".getBytes())) {
            Utilities.attemptRequest(injector.getService(), request);
            Utilities.attemptRequest(injector.getService(), request);

            IHttpRequestResponse poisoned = Utilities.attemptRequest(injector.getService(), Utilities.helpers.addParameter(base.getRequest(), cacheBuster));
            if (Utilities.containsBytes(poisoned.getResponse(), "wrtqv".getBytes())){
                Utilities.log("Successful cache poisoning check");
                Utilities.callbacks.addScanIssue(new CustomScanIssue(poisoned.getHttpService(), Utilities.getURL(poisoned), poisoned, "Cache poisoning", "Cache poisoning: '"+param+"'. Disregard the request and look for wrtqv in the response", "High", "Firm", "Investigate"));
                return poisoned;
            }
        }
        Utilities.log("Failed cache poisoning check");
        return null;
    }

    private void addNewKeys(ArrayList<String> keys, ParamAttack state, int bucketSize, ParamHolder paramBuckets, ArrayList<String> candidates, Attack paramGuess) {
        if (!Utilities.DYNAMIC_KEYLOAD) {
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
        IHttpRequestResponse scanBaseAttack = injector.probeAttack(scanBasePayload).getFirstRequest();
        byte[] scanBaseGrep = Utilities.helpers.stringToBytes(insertionPoint.calculateValue(scanBasePayload));
        int start = Utilities.helpers.indexOf(scanBaseAttack.getRequest(), scanBaseGrep, true, 0, scanBaseAttack.getRequest().length);
        int end = start + scanBaseGrep.length;
        Utilities.doActiveScan(scanBaseAttack, new int[]{start, end});
    }

    private static boolean findPersistent(IHttpRequestResponse baseRequestResponse, Attack paramGuess, String attackID, CircularFifoQueue<String> recentParams, ArrayList<String> currentParams, HashSet<String> alreadyReported) {
        if (currentParams == null) {
            currentParams = new ArrayList<>();
        }

        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        if (failResp == null) {
            return false;
        }

        for(Iterator<String> params = recentParams.iterator(); params.hasNext();) {
            String param = params.next();
            if(currentParams.contains(param) || alreadyReported.contains(param)) {
                continue;
            }

            String canary = Utilities.toCanary(param.split("~", 2)[0]) + attackID;
            if (Utilities.helpers.indexOf(failResp, Utilities.helpers.stringToBytes(canary), false, 1, failResp.length - 1) != -1 &&
                    Utilities.helpers.indexOf(paramGuess.getFirstRequest().getRequest(), Utilities.helpers.stringToBytes(canary), false, 1, paramGuess.getFirstRequest().getRequest().length - 1) == -1) {
                Utilities.out(Utilities.getURL(baseRequestResponse) + " identified persistent parameter: " + param);
                params.remove();
                Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), paramGuess.getFirstRequest(), "Secret parameter", "Found persistent parameter: '"+param+"'. Disregard the request and look for " + canary + " in the response", "High", "Firm", "Investigate"));
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

