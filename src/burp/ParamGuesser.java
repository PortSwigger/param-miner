package burp;

import com.google.gson.JsonElement;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintStream;
import java.util.*;

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
        Utilities.out("Aborting param bruteforce");
        Utilities.unloaded.set(true);
    }

    static String getKey(String param) {
        String[] keys = param.split(":");
        for (int i=keys.length-1; i>=0; i--) {
            if (Utilities.parseArrayIndex(keys[i]) == -1) {
                return keys[i];
            }
        }
        return param;
    }

    static String permute(String param) {
        String[] keys = param.split(":");
        for (int i=keys.length-1; i>=0; i--) {
            if (Utilities.parseArrayIndex(keys[i]) == -1) {
                keys[i] += Utilities.randomString(3);
                break;
            }
        }
        return String.join(":", keys);
    }

    static ArrayList<String> calculatePayloads(IHttpRequestResponse baseRequestResponse, byte type, ParamGrabber paramGrabber) {
        IRequestInfo info = Utilities.helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<IParameter> currentParams = info.getParameters();
        ArrayList<String> params = new ArrayList<>();

        HashSet<String> witnessedParams = new HashSet<>();
        for (IParameter param : currentParams) {
            if (param.getType() == type) {
                witnessedParams.add(param.getName());
            }
        }

        ArrayList<String> rawRequestParams = Json.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>());
        HashMap<String, String> requestParams = new HashMap<>();
        for (String entry: rawRequestParams) { // todo give precedence to shallower keys
            String[] parsed = Json.parseKey(entry);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
            witnessedParams.add(parsed[1]);
            witnessedParams.add(parsed[0]);
        }

        params.addAll(Json.getAllKeys(baseRequestResponse.getResponse(), requestParams));

        HashMap<Integer, Set<String>> responses = new HashMap<>();
        for (JsonElement resp: paramGrabber.getSavedJson()) {
            HashSet<String> keys = new HashSet<>(Json.getAllKeys(resp, requestParams));
            int matches = 0;
            for (String requestKey: requestParams.keySet()) {
                if (keys.contains(requestKey)) {
                    matches++;
                }
            }

            // if there are no matches, don't bother with prefixes
            // todo use root (or non-leaf) objects only
            if(matches < 2) {
                HashSet<String> filteredKeys = new HashSet<>();
                for(String key: keys) {
                    String lastKey = Json.parseKey(key)[1];
                    if (Utilities.parseArrayIndex(lastKey) < 3) {
                        filteredKeys.add(Json.parseKey(key)[1]);
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
            Utilities.out("Loading keys with "+key+" matches");
            ArrayList<String> sortedByLength = new ArrayList<>(responses.get(key));
            sortedByLength.sort(new LengthCompare());
            //for (String i: sortedByLength) {
            //    Utilities.out(i);
            //}
            params.addAll(sortedByLength);
        }

        if (params.size() > 0) {
            Utilities.out("Loaded " + new HashSet<>(params).size() + " params from response JSON");
        }

        params.addAll(paramGrabber.getSavedGET());

        params.addAll(Utilities.paramNames);

        // only use keys if the request isn't JSON
        // todo accept two levels of keys if it's using []
        if (type != IParameter.PARAM_JSON) {
            for(int i=0;i<params.size();i++) {
                params.set(i, Json.parseKey(params.get(i))[1]);
            }
        }

        // de-dupe without losing the ordering
        params = new ArrayList<>(new LinkedHashSet<>(params));

        // don't both using parameters that are already present
        Iterator<String> refiner = params.iterator();
        while (refiner.hasNext()) {
            String candidate = refiner.next();
            String finalKey = getKey(candidate);
            if (witnessedParams.contains(candidate) ||
                    witnessedParams.contains(finalKey)) {
                refiner.remove();
            }

        }


        return params;
    }

    ArrayList<Attack> guessParams(IHttpRequestResponse baseRequestResponse, byte type) {
        if (baseRequestResponse.getResponse() == null) {
            Utilities.out("Baserequest has no response - fetching...");
            baseRequestResponse = Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
        }

        ArrayList<Attack> attacks = new ArrayList<>();
        String targetURL = baseRequestResponse.getHttpService().getHost();
        ArrayList<String> params = calculatePayloads(baseRequestResponse, type, paramGrabber);

        HashMap<String, String> requestParams = new HashMap<>();
        for (String entry: Json.getAllKeys(baseRequestResponse.getRequest(), new HashMap<>())) { // todo give precedence to shallower keys
            String[] parsed = Json.parseKey(entry);
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }

        try {
            final String payload = "<a`'\\\"${{\\\\";


            IScannerInsertionPoint insertionPoint = getInsertionPoint(baseRequestResponse, type, payload);

            PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);

            Utilities.out("Initiating parameter name bruteforce on "+ targetURL);
            HashSet<String> reportedInputs = new HashSet<>();
            Attack base = getBaselineAttack(injector);
            Attack paramGuess;
            Attack failAttack;
            int max = Math.max(params.size(), 300);

            for (int i = 0; i<max; i++) {

                String candidate = params.get(i);
                //if(1==1) break;

                paramGuess = injector.buildAttack(candidate, false);

                if (!Utilities.similar(base, paramGuess)) {
                    Attack confirmParamGuess = injector.buildAttack(candidate, false);
                    failAttack = injector.buildAttack(permute(candidate), false);

                    // this to prevent error messages obscuring persistent inputs
                    findPersistent(baseRequestResponse, targetURL, params, reportedInputs, failAttack, i);

                    base.addAttack(failAttack);
                    if (!Utilities.similar(base, confirmParamGuess)) {
                        Probe validParam = new Probe(targetURL+" found param: " + candidate, 4, candidate);
                        validParam.setEscapeStrings(permute(candidate), permute(candidate));
                        validParam.setRandomAnchor(false);
                        validParam.setPrefix(Probe.REPLACE);
                        ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
                        if (!confirmed.isEmpty()) {
                            Utilities.out(targetURL+" identified parameter: " + candidate);
                            attacks.addAll(confirmed);
                        }
                        else {
                            Utilities.out(targetURL+" failed to confirm: "+candidate);
                        }
                    } else {
                        Utilities.out(targetURL + " couldn't replicate: " + candidate);
                        base.addAttack(paramGuess);
                    }
                }

                for(String key: Json.getAllKeys(paramGuess.getFirstRequest().getResponse(), requestParams)){
                    String[] parsed = Json.parseKey(key);
                    if (!(params.contains(key) || params.contains(parsed[1]) || requestParams.containsKey(parsed[1]) || parsed[1].equals(candidate))) {
                        Utilities.out("Found new key: "+key);
                        params.add(i+1, key);
                        max++;
                        paramGrabber.saveParams(paramGuess.getFirstRequest());
                    }
                }

                if (findPersistent(baseRequestResponse, targetURL, params, reportedInputs, paramGuess, i)) {
                    base = getBaselineAttack(injector);
                }



            }
            Utilities.out("Parameter name bruteforce complete: "+targetURL);

        }
        catch (RuntimeException e) {
            Utilities.out("Parameter name bruteforce aborted: "+targetURL);
            e.printStackTrace();
            e.printStackTrace(new PrintStream(Utilities.callbacks.getStdout()));
            Utilities.out(e.getMessage());
            return attacks;
        }

        return attacks;
    }

    private static boolean findPersistent(IHttpRequestResponse baseRequestResponse, String targetURL, ArrayList<String> params, HashSet<String> reportedInputs, Attack paramGuess, int i) {
        byte[] failResp = paramGuess.getFirstRequest().getResponse();
        for (int k = 1; k < i && k<4; k++) {
            String lastPayload = params.get(i - k);
            String canary = Utilities.mangle(lastPayload);
            lastPayload = lastPayload.substring(lastPayload.lastIndexOf(':')+1);
            if (reportedInputs.contains(lastPayload)) {
                continue;
            }
            if (Utilities.helpers.indexOf(failResp, Utilities.helpers.stringToBytes(canary), false, 1, failResp.length - 1) != -1) {
                Utilities.out(targetURL + " identified persistent parameter: " + lastPayload);
                Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), paramGuess.getFirstRequest(), "Persistent param: " + lastPayload, "Look for " + canary + " in the response", "High", "Firm", "Investigate"));
                reportedInputs.add(lastPayload);
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

    private static IScannerInsertionPoint getInsertionPoint(IHttpRequestResponse baseRequestResponse, byte type, String payload) {
        return type == IParameter.PARAM_JSON ?
                        new JsonParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type) :
                        new ParamNameInsertionPoint(baseRequestResponse.getRequest(), "guesser", payload, type);
    }

    static ArrayList<Attack> guessBackendParams(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        String baseValue = insertionPoint.getBaseValue();
        PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);
        String targetURL = baseRequestResponse.getHttpService().getHost();
        Utilities.out("Initiating parameter name bruteforce on "+ targetURL);
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
            Utilities.out("Parameter name bruteforce complete: "+targetURL);
        }
        catch (RuntimeException e) {
            Utilities.out("Parameter name bruteforce aborted: "+targetURL);
        }

        return attacks;
    }

}

class OfferParamGuess implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private ParamGrabber paramGrabber;

    public OfferParamGuess(final IBurpExtenderCallbacks callbacks, ParamGrabber paramGrabber) {
        this.callbacks = callbacks;
        this.paramGrabber = paramGrabber;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();
        JMenuItem probeButton = new JMenuItem("Guess GET parameters");
        probeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber));
        options.add(probeButton);

        if (reqs.length == 1) {
            IHttpRequestResponse req = reqs[0];
            byte[] resp = req.getRequest();
            if (Utilities.countMatches(resp, Utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
                JMenuItem backendProbeButton = new JMenuItem("*Identify backend parameters*");
                backendProbeButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber));
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
                    postProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber));
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

class TriggerParamGuesser implements ActionListener {
    private IHttpRequestResponse[] reqs;
    private boolean backend;
    private byte type;
    private ParamGrabber paramGrabber;

    TriggerParamGuesser(IHttpRequestResponse[] reqs, boolean backend, byte type, ParamGrabber paramGrabber) {
        this.paramGrabber = paramGrabber;
        this.backend = backend;
        this.reqs = reqs;
        this.type = type;
    }

    public void actionPerformed(ActionEvent e) {
        for (IHttpRequestResponse req: reqs) {
            Runnable runnable = new ParamGuesser(req, backend, type, paramGrabber);
            (new Thread(runnable)).start();
        }
    }
}