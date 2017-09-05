package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

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

    public ParamGuesser(IHttpRequestResponse req, boolean backend, byte type) {
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

    static ArrayList<String> getAllKeys(JsonElement json, String prefix, HashMap<String, String> witnessedParams) {
        ArrayList<String> keys = new ArrayList<>();

        // todo handle arrays
        if (json.isJsonObject()) {
            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                if (witnessedParams.containsKey(entry.getKey())) {
                    Utilities.out("Recognised '"+entry.getKey()+"', replacing prefix '"+prefix+"' with '"+ witnessedParams.get(entry.getKey())+"'");
                    prefix = witnessedParams.get(entry.getKey());
                    break;
                }
            }

            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                keys.addAll(getAllKeys(entry.getValue(), prefix + ":" + entry.getKey(), witnessedParams));
            }

            keys.add(prefix);

        } else if (json.isJsonArray()) {
            JsonArray hm = json.getAsJsonArray();
            int i = 0;
            for (JsonElement x: hm) {
                keys.addAll(getAllKeys(x, prefix + ":" + Integer.toString(i++), witnessedParams));
            }
        }


        else {
            if (prefix.startsWith(":")) {
                prefix = prefix.substring(1);
            }
            Utilities.out(prefix);
            keys.add(prefix);
        }


        return keys;
    }

    static ArrayList<String> getParamsFromResponse(IHttpRequestResponse baseRequestResponse, HashSet<String> witnessedParams) {
        String body = Utilities.getBody(baseRequestResponse.getResponse());


        ArrayList<String> found = new ArrayList<>();
        try {
            JsonParser parser = new JsonParser();
            HashMap<String, String> requestParams = new HashMap<>();

            // todo give precedence to shallower keys
            ArrayList<String> rawRequestParams = getAllKeys(parser.parse(Utilities.getBody(baseRequestResponse.getRequest())), "", new HashMap<String, String>());
            for (String entry: rawRequestParams) {
                int keyStart = entry.lastIndexOf(':');
                String prefix;
                String key;
                if (keyStart != -1) {
                    prefix = entry.substring(0, keyStart);
                    key = entry.substring(keyStart + 1);
                }
                else {
                    prefix = "";
                    key = entry;
                }
                requestParams.putIfAbsent(key, prefix);
            }

            found = getAllKeys(parser.parse(body), "", requestParams);
        }
        catch (Exception e) {

        }

        return found;
    }

    static ArrayList<Attack> guessParams(IHttpRequestResponse baseRequestResponse, byte type) {
        ArrayList<Attack> attacks = new ArrayList<>();
        String targetURL = baseRequestResponse.getHttpService().getHost();

        IRequestInfo info = Utilities.helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<IParameter> currentParams = info.getParameters();

        HashSet<String> witnessedParams = new HashSet<>();
        for (IParameter param : currentParams) {
            if (param.getType() == type) {
                witnessedParams.add(param.getName());
            }
        }

        ArrayList<String> params = getParamsFromResponse(baseRequestResponse, witnessedParams);
        if (params.size() > 0) {
            Utilities.out("Loaded "+params.size() +" params from response JSON");
        }
        //params.addAll(Utilities.paramNames);

        try {
            final String payload = "<a`'\\\"${{\\\\";


            IScannerInsertionPoint insertionPoint = getInsertionPoint(baseRequestResponse, type, payload);

            PayloadInjector injector = new PayloadInjector(baseRequestResponse, insertionPoint);

            Utilities.out("Initiating parameter name bruteforce on "+ targetURL);
            HashSet<String> reportedInputs = new HashSet<>();
            Attack base = getBaselineAttack(injector);
            Attack paramGuess = null;
            Attack lastAttack;
            Attack failAttack;

            for (int i = 0; i < 100; i++) { // params.size()
                String candidate = params.get(i);
                if (witnessedParams.contains(candidate)) {
                    continue;
                }

                paramGuess = injector.buildAttack(candidate, false);

                if (!Utilities.similar(base, paramGuess)) {
                    Attack confirmParamGuess = injector.buildAttack(candidate, false);
                    failAttack = injector.buildAttack(candidate + "z", false);
                    base.addAttack(failAttack);
                    if (!Utilities.similar(base, confirmParamGuess)) {
                        Probe validParam = new Probe(targetURL+" found param: " + candidate, 4, candidate);
                        validParam.setEscapeStrings(candidate+Utilities.randomString(3), candidate+Utilities.randomString(2));
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
                        base = getBaselineAttack(injector); // re-benchmark
                        reportedInputs.add(lastPayload);
                    }
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

    public OfferParamGuess(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();
        JMenuItem probeButton = new JMenuItem("Guess GET parameters");
        probeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL));
        options.add(probeButton);

        if (reqs.length == 1) {
            IHttpRequestResponse req = reqs[0];
            byte[] resp = req.getRequest();
            if (Utilities.countMatches(resp, Utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
                JMenuItem backendProbeButton = new JMenuItem("*Identify backend parameters*");
                backendProbeButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL));
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
                    postProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, type));
                    options.add(postProbeButton);
                }
            }
        }

        return options;
    }
}

class TriggerParamGuesser implements ActionListener {
    private IHttpRequestResponse[] reqs;
    private boolean backend;
    private byte type;

    TriggerParamGuesser(IHttpRequestResponse[] reqs, boolean backend, byte type) {
        this.backend = backend;
        this.reqs = reqs;
        this.type = type;
    }

    public void actionPerformed(ActionEvent e) {
        for (IHttpRequestResponse req: reqs) {
            Runnable runnable = new ParamGuesser(req, backend, type);
            (new Thread(runnable)).start();
        }
    }
}