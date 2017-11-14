package burp;

import com.google.gson.JsonElement;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;

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
    private ParamGrabber paramGrabber;

    public ParamGuesser(IHttpRequestResponse req, boolean backend, byte type, ParamGrabber paramGrabber) {
        this.paramGrabber = paramGrabber;
        this.req = req;
        this.backend = backend;
        this.type = type;
    }

    public void run() {

        IRequestInfo info = Utilities.helpers.analyzeRequest(req);
        List<IParameter> params = info.getParameters();

        if (req.getResponse() == null) {
            Utilities.log("Baserequest has no response - fetching...");
            req = Utilities.callbacks.makeHttpRequest(req.getHttpService(), req.getRequest());
        }

        if(backend) {

            for (IParameter param : params) {
                String key = null;
                String[] keys = {"%26zq=%253c", "!zq=%253c"};
                for (String test : keys) {
                    if (param.getValue().contains(test)) {
                        key = test;
                        break;
                    }
                }

                if (key != null) {
                    String originalValue = param.getValue().substring(0, param.getValue().indexOf(key));
                    ParamInsertionPoint insertionPoint = new ParamInsertionPoint(req.getRequest(), param.getName(), originalValue, param.getType());
                    ArrayList<Attack> paramGuesses = guessBackendParams(req, insertionPoint);
                    if (!paramGuesses.isEmpty()) {
                        Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req));
                    }
                    break;
                }

            }
        }
        else {
            ArrayList<Attack> paramGuesses = guessParams(req, type);
            if (!paramGuesses.isEmpty()) {
                Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(paramGuesses.toArray((new Attack[paramGuesses.size()])), req));
            }
        }
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting param bruteforce");
        Utilities.unloaded.set(true);
    }

    static ArrayList<String> calculatePayloads(IHttpRequestResponse baseRequestResponse, byte type, ParamGrabber paramGrabber) {
        ArrayList<String> params = new ArrayList<>();

        // collect keys in request, for key skipping, matching and re-mapping
        HashMap<String, String> requestParams = new HashMap<>();
        for (String entry: Keysmith.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) { // todo give precedence to shallower keys
            String[] parsed = Keysmith.parseKey(entry);
            Utilities.log("Request param: " +parsed[1]);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        // add JSON from observed responses,
        params.addAll(Keysmith.getAllKeys(baseRequestResponse.getResponse(), requestParams));

        if(baseRequestResponse.getRequest()[0] != 'G') {
            IHttpRequestResponse getreq = Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    Utilities.helpers.toggleRequestMethod(baseRequestResponse.getRequest()));
            params.addAll(Keysmith.getAllKeys(getreq.getResponse(), requestParams));
        }


        HashMap<Integer, Set<String>> responses = new HashMap<>();

        Iterator<JsonElement> savedJson = paramGrabber.getSavedJson().iterator();
        while (savedJson.hasNext()) {
            JsonElement resp = null;
            try {
                resp = savedJson.next();
            }
            catch (NoSuchElementException e) {
                break;
            }

            HashSet<String> keys = new HashSet<>(Keysmith.getJsonKeys(resp, requestParams));
            int matches = 0;
            for (String requestKey: keys) {
                if (requestParams.containsKey(requestKey) || requestParams.containsKey(Keysmith.parseKey(requestKey)[1])) {
                    matches++;
                }

            }

            // if there are no matches, don't bother with prefixes
            // todo use root (or non-leaf) objects only
            if(matches < 1) {
                //Utilities.out("No matches, discarding prefix");
                HashSet<String> filteredKeys = new HashSet<>();
                for(String key: keys) {
                    String lastKey = Keysmith.parseKey(key)[1];
                    if (Utilities.parseArrayIndex(lastKey) < 3) {
                        filteredKeys.add(Keysmith.parseKey(key)[1]);
                    }
                }
                keys = filteredKeys;
            }

            Integer matchKey = matches;
            if(responses.containsKey(matchKey)) {
                responses.get(matchKey).addAll(keys);
            }
            else {
                responses.put(matchKey, keys);
            }
        }


        final TreeSet<Integer> sorted = new TreeSet<>(Collections.reverseOrder());
        sorted.addAll(responses.keySet());
        for(Integer key: sorted) {
            Utilities.log("Loading keys with "+key+" matches");
            ArrayList<String> sortedByLength = new ArrayList<>(responses.get(key));
            sortedByLength.sort(new LengthCompare());
            params.addAll(sortedByLength);
        }

        if (params.size() > 0) {
            Utilities.log("Loaded " + new HashSet<>(params).size() + " params from response");
        }

        params.addAll(paramGrabber.getSavedGET());

        params.addAll(Utilities.paramNames);

        // only use keys if the request isn't JSON
        // todo accept two levels of keys if it's using []
        //if (type != IParameter.PARAM_JSON) {
        //    for(int i=0;i<params.size();i++) {
        //        params.set(i, Keysmith.parseKey(params.get(i))[1]);
        //    }
        //}

        // de-dupe without losing the ordering
        params = new ArrayList<>(new LinkedHashSet<>(params));

        // don't both using parameters that are already present
        Iterator<String> refiner = params.iterator();
        while (refiner.hasNext()) {
            String candidate = refiner.next();
            String finalKey = Keysmith.getKey(candidate);
            if (requestParams.containsKey(candidate) ||
                    requestParams.containsKey(finalKey) || requestParams.containsValue(candidate) || requestParams.containsValue(finalKey)) {
                refiner.remove();
            }

        }


        return params;
    }

    ArrayList<Attack> guessParams(IHttpRequestResponse baseRequestResponse, byte type) {
        ArrayList<Attack> attacks = new ArrayList<>();
        String targetURL = baseRequestResponse.getHttpService().getHost();
        ArrayList<String> params = calculatePayloads(baseRequestResponse, type, paramGrabber);
        String attackID = Utilities.mangle(Arrays.hashCode(baseRequestResponse.getRequest())+"|"+System.currentTimeMillis());
        
        byte[] invertedBase = Utilities.helpers.toggleRequestMethod(baseRequestResponse.getRequest());

        HashMap<String, String> requestParams = new HashMap<>();
        for (String entry: Keysmith.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) {
            String[] parsed = Keysmith.parseKey(entry);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        try {
            final String payload = ""; // formerly "<a`'\\\"${{\\\\"


            IScannerInsertionPoint insertionPoint = getInsertionPoint(baseRequestResponse, type, payload, attackID);

            PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);

            Utilities.log("Initiating parameter name bruteforce on "+ targetURL);
            CircularFifoQueue<String> recentParams = new CircularFifoQueue<>(8);

            Attack base = getBaselineAttack(injector);
            Attack paramGuess = null;
            Attack failAttack;
            int max = max(params.size(), 300);
            max = min(max, 1000);

            //String ref = Utilities.getHeader(baseRequestResponse.getRequest(), "Referer");
            //HashMap<String, Attack> baselines = new HashMap<>();
            //baselines.put(ref, new Attack(baseRequestResponse));
            Attack altBase = new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase));
            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));

            for (int i = 0; i<max; i++) {

                String candidate = params.get(i);

                ArrayList<String> variants = new ArrayList<>();

                variants.add(candidate);
                if(candidate.contains("~")) {
                    variants.add(candidate.split("~", 2)[0]);
                }

                for (String variant: variants) {
                    paramGuess = injector.buildAttack(variant, false);

                    if (!candidate.contains("~")) {
                        if (findPersistent(baseRequestResponse, paramGuess, attackID, recentParams)) {
                            base = getBaselineAttack(injector);
                        }
                        recentParams.add(variant);
                    }

                    if (!Utilities.similar(base, paramGuess)) {
                        Attack confirmParamGuess = injector.buildAttack(variant, false);

                        failAttack = injector.buildAttack(Keysmith.permute(variant), false);

                        // this to prevent error messages obscuring persistent inputs
                        findPersistent(baseRequestResponse, failAttack, attackID, recentParams);

                        base.addAttack(failAttack);
                        if (!Utilities.similar(base, confirmParamGuess)) {
                            Probe validParam = new Probe("Found unlinked param: " + variant, 4, variant);
                            validParam.setEscapeStrings(Keysmith.permute(variant), Keysmith.permute(variant));
                            validParam.setRandomAnchor(false);
                            validParam.setPrefix(Probe.REPLACE);
                            ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
                            if (!confirmed.isEmpty()) {
                                Utilities.out(targetURL + " identified parameter: " + variant);
                                Utilities.callbacks.addScanIssue(Utilities.reportReflectionIssue(confirmed.toArray(new Attack[2]), baseRequestResponse));
                                //attacks.addAll(confirmed);
                                break;
                            } else {
                                Utilities.log(targetURL + " failed to confirm: " + variant);
                            }
                        } else {
                            Utilities.log(targetURL + " couldn't replicate: " + variant);
                            base.addAttack(paramGuess);
                        }
                    }
                    else {
                        Attack paramGrab = new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase));
                        findPersistent(baseRequestResponse, paramGrab, attackID, recentParams);

                        if (!Utilities.similar(altBase, paramGrab)) {
                            Utilities.out("Potential GETbase param: "+variant);
                            injector.buildAttack(Keysmith.permute(variant), false);
                            altBase.addAttack(new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase)));
                            injector.buildAttack(variant, false);

                            paramGrab = new Attack(Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), invertedBase));
                            if (!Utilities.similar(altBase, paramGrab)) {
                                Utilities.out("Confirmed GETbase param: "+variant);
                                IHttpRequestResponse[] evidence = new IHttpRequestResponse[3];
                                evidence[0] = altBase.getFirstRequest();
                                evidence[1] = paramGuess.getFirstRequest();
                                evidence[2] = paramGrab.getFirstRequest();
                                Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), evidence, "Second-order param: " + candidate, "Review evidence", "High", "Firm", "Investigate"));
                            }
                        }

                    }

                    for(String key: Keysmith.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams)){
                        String[] parsed = Keysmith.parseKey(key);
                        if (!(params.contains(key) || params.contains(parsed[1]) || requestParams.containsKey(parsed[1]) || parsed[1].equals(candidate) || parsed[1].equals(variant))) {
                            Utilities.out("Found new key: "+key);
                            params.add(i+1, key);
                            max++;
                            paramGrabber.saveParams(paramGuess.getFirstRequest());
                        }
                    }
                }
            }
            Utilities.log("Parameter name bruteforce complete: "+targetURL);

        }
        catch (RuntimeException e) {
            Utilities.log("Parameter name bruteforce aborted: "+targetURL);
            if(!e.getMessage().contains("Extension unloaded")) {
                e.printStackTrace();
                e.printStackTrace(new PrintStream(Utilities.callbacks.getStdout()));
                Utilities.out(e.getMessage());
            }
            return attacks;
        }

        return attacks;
    }

    private static boolean findPersistent(IHttpRequestResponse baseRequestResponse, Attack paramGuess, String attackID, CircularFifoQueue<String> recentParams) {
        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        if (failResp == null) {
            return false;
        }

        for(Iterator<String> params = recentParams.iterator(); params.hasNext();) {
            String param = params.next();
            String canary = Utilities.toCanary(param.split("~", 2)[0]) + attackID;
            if (Utilities.helpers.indexOf(failResp, Utilities.helpers.stringToBytes(canary), false, 1, failResp.length - 1) != -1) {
                Utilities.log(Utilities.getURL(baseRequestResponse) + " identified persistent parameter: " + param);
                params.remove();
                Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), paramGuess.getFirstRequest(), "Persistent param: " + param, "Disregard the request and look for " + canary + " in the response", "High", "Firm", "Investigate"));
                return true;
            }
        }
        return false;
    }

    private static Attack getBaselineAttack(PayloadInjector injector) {
        Attack base = injector.buildAttack(Utilities.randomString(6), false);
        for(int i=0; i<4; i++) {
            base.addAttack(injector.buildAttack(Utilities.randomString((i+1)*(i+1)), false));
        }
        return base;
    }

    private static IScannerInsertionPoint getInsertionPoint(IHttpRequestResponse baseRequestResponse, byte type, String payload, String attackID) {
        return type == IParameter.PARAM_JSON ?
                        new JsonParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID) :
                        new RailsInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type, attackID);
    }

    static ArrayList<Attack> guessBackendParams(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        String baseValue = insertionPoint.getBaseValue();
        PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);
        String targetURL = baseRequestResponse.getHttpService().getHost();
        Utilities.log("Initiating parameter name bruteforce on " + targetURL);

        final String breaker = "=%3c%61%60%27%22%24%7b%7b%5c";
        Attack base = injector.buildAttack(baseValue+"&"+Utilities.randomString(6)+ breaker, false);

        for(int i=0; i<4; i++) {
            base.addAttack(injector.buildAttack(baseValue+"&"+Utilities.randomString((i+1)*(i+1))+ breaker, false));
        }

        ArrayList<Attack> attacks = new ArrayList<>();
        try {
            for (int i = 0; i < Utilities.paramNames.size(); i++) { // i<Utilities.paramNames.size();
                String candidate = Utilities.paramNames.get(i);
                Attack paramGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
                if (!Utilities.similar(base, paramGuess)) {
                    Attack confirmParamGuess = injector.buildAttack(baseValue + "&" + candidate + breaker, false);
                    base.addAttack(injector.buildAttack(baseValue + "&" + candidate + "z"+breaker, false));
                    if (!Utilities.similar(base, confirmParamGuess)) {
                        Probe validParam = new Probe("Backend param: " + candidate, 4, "&" + candidate + breaker, "&" + candidate + "=%3c%62%60%27%22%24%7b%7b%5c");
                        validParam.setEscapeStrings("&" + Utilities.randomString(candidate.length()) + breaker, "&" + candidate + "z"+breaker);
                        validParam.setRandomAnchor(false);
                        ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
                        if (!confirmed.isEmpty()) {
                            Utilities.out("Identified backend parameter: " + candidate);
                            attacks.addAll(confirmed);
                        }
                    } else {
                        base.addAttack(paramGuess);
                    }
                }

            }
            Utilities.log("Parameter name bruteforce complete: "+targetURL);
        }
        catch (RuntimeException e) {
            Utilities.log("Parameter name bruteforce aborted: "+targetURL);
        }

        return attacks;
    }

}

class OfferParamGuess implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private ParamGrabber paramGrabber;
    private ThreadPoolExecutor taskEngine;

    public OfferParamGuess(final IBurpExtenderCallbacks callbacks, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
        this.callbacks = callbacks;
        this.paramGrabber = paramGrabber;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        if(reqs.length == 0) {
            return options;
        }

        JMenuItem probeButton = new JMenuItem("Guess GET parameters");
        probeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine));
        options.add(probeButton);

        if (reqs.length == 1 && reqs[0] != null) {
            IHttpRequestResponse req = reqs[0];
            byte[] resp = req.getRequest();
            if (Utilities.countMatches(resp, Utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
                JMenuItem backendProbeButton = new JMenuItem("*Identify backend parameters*");
                backendProbeButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber, taskEngine));
                options.add(backendProbeButton);
            }

            if (resp[0] == 'P') {
                IRequestInfo info = Utilities.helpers.analyzeRequest(req);
                List<IParameter> params = info.getParameters();

                HashSet<Byte> paramTypes = new HashSet<>();
                for (IParameter param : params) {
                    if (param.getType() != IParameter.PARAM_URL) {
                        paramTypes.add(param.getType());
                    }
                }

                for (Byte type : paramTypes) {
                    String humanType = "Unknown";
                    switch(type) {
                        case 0:
                            humanType = "URL";
                            break;
                        case 1:
                            humanType = "body";
                            break;
                        case 2:
                            humanType = "cookie";
                            break;
                        case 3:
                            humanType = "XML";
                            break;
                        case 4:
                            humanType = "XML attribute";
                            break;
                        case 5:
                            humanType = "multipart";
                            break;
                        case 6:
                            humanType = "JSON";
                            break;
                    }

                    JMenuItem postProbeButton = new JMenuItem("Guess " + humanType + " parameter");
                    postProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber, taskEngine));
                    options.add(postProbeButton);
                }
            }
        }

        return options;
    }
}

class LengthCompare implements Comparator<String> {
    public int compare(String o1, String o2) {
        return Integer.compare(o1.length(), o2.length());
    }
}

class TriggerParamGuesser implements ActionListener, Runnable {
    private IHttpRequestResponse[] reqs;
    private boolean backend;
    private byte type;
    private ParamGrabber paramGrabber;
    private ThreadPoolExecutor taskEngine;

    TriggerParamGuesser(IHttpRequestResponse[] reqs, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
        this.paramGrabber = paramGrabber;
        this.backend = backend;
        this.reqs = reqs;
        this.type = type;
    }

    public void actionPerformed(ActionEvent e) {
        Runnable runnable = new TriggerParamGuesser(reqs, backend, type, paramGrabber, taskEngine);
        (new Thread(runnable)).start();
    }

    public void run() {
        Utilities.out("Queuing "+reqs.length+" tasks");

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        int thread_count = taskEngine.getCorePoolSize();
        Queue<String> cache = new CircularFifoQueue<>(thread_count);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.out("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();
                String host = req.getHttpService().getHost();

                if (!cache.contains(host)) {
                    cache.add(host);
                    left.remove();
                    Utilities.out("Adding request on "+host+" to queue");
                    taskEngine.execute(new ParamGuesser(req, backend, type, paramGrabber));
                } else {
                    remainingHosts.add(host);
                }
            }
            if (remainingHosts.size() <= 1) {
                left = reqlist.iterator();
                while (left.hasNext()) {
                    taskEngine.execute(new ParamGuesser(left.next(), backend, type, paramGrabber));
                }
                break;
            }
            else {
                cache = new CircularFifoQueue<>(min(remainingHosts.size()-1, thread_count));
            }
        }

    }
}