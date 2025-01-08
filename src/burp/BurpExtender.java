package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.*;


public class BurpExtender implements IBurpExtender, IExtensionStateListener, BurpExtension {
    private static final String name = "Param Miner";
    private static final String version = "1.53";
    private ThreadPoolExecutor taskEngine;
    static ParamGrabber paramGrabber;
    static SettingsBox configSettings = new SettingsBox();
    static SettingsBox guessSettings = new SettingsBox();

    @Override
    public void initialize(MontoyaApi api) {
        Utilities.montoyaApi = api;
        BulkUtilities.registerContextMenu();
        api.userInterface().registerContextMenuItemsProvider(new OfferHostnameOverride());
    }
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks, new HashMap<>(), name);

        // config only (currently param-guess displays everything)
        configSettings.register("Add 'fcbz' cachebuster", false, "Add a static cache-buster to all outbound requests, to avoid manual cache poisoning probes affecting other users");
        configSettings.register("Add dynamic cachebuster", false, "Add a dynamic cache-buster to all requests, to avoid seeing cached responses");
        //configSettings.register("Add header cachebuster", false);
        configSettings.register("learn observed words", false, "During Burp's passive scanning, record all words seen in the response and use them when guessing parameters. ");
        configSettings.register("enable auto-mine", false, "Automatically launch param guessing attacks on traffic as it passes through the proxy");
        configSettings.register("auto-mine headers", false, "When auto-mining proxied traffic, guess headers");
        configSettings.register("auto-mine cookies", false, "When auto-mining proxied traffic, guess cookies");
        configSettings.register("auto-mine params", false, "When auto-mining proxied traffic, guess parameters");
        configSettings.register("auto-nest params", false, "When guessing parameters in JSON, attempt to guess deeper in nested structures. Might not work.");

        // param-guess only
        //guessSettings.importSettings(globalSettings);
        guessSettings.register("quantitative diff keys", "time", "Use timing info to detect parameters. Disable this to make Param Miner faster."); // this overwrites the setting from bulkScan
        guessSettings.register("learn observed words", false);
        guessSettings.register("skip boring words", true, "When mining headers, don't check for well known and typically not very exciting headers");
        guessSettings.register("only report unique params", false, "Only report a parameter with a given name once, regardless of how many endpoints are scanned");
        guessSettings.register("response-headers", true, "Extract words from the target response headers, and use these to guess params");
        guessSettings.register("response-body", true, "Extract words from the target response body, and use these to guess params");
        guessSettings.register("request", true, "Extract words from the target request, and use these to guess params. Highly recommended.");
        guessSettings.register("use basic wordlist", true, "When guessing params, use the core wordlist");
        guessSettings.register("use bonus wordlist", false, "When guessing params, also use a generic wordlist");
        guessSettings.register("use assetnote params", false, "When guessing params, use the assetnote wordlist");
        guessSettings.register("use custom wordlist", false, "Load a custom wordlist from the configured path");
        guessSettings.register("custom wordlist path", "/usr/share/dict/words", "Load a custom wordlist from the configured path");
        guessSettings.register("bruteforce", false, "When all the wordlist have run out, switch to guessing params with a never-ending pure bruteforce attack.");
        guessSettings.register("skip uncacheable", false, "Refuse to guess params on responses that aren't cacheable?");
        guessSettings.register("dynamic keyload", false, "When guessing params, extract words from every observed response. This is very powerful and quite buggy.");
        guessSettings.register("max one per host", false);
        guessSettings.register("max one per host+status", false);
        guessSettings.register("probe identified params", true, "Attempt to identify what type of input discovered parameters expect.");
        guessSettings.register("scan identified params", false, "Launch an active scan against every discovered parameter");
        guessSettings.register("fuzz detect", false, "Detect parameters by specifying a fuzz-string as a value, designed to cause errors");
        guessSettings.register("carpet bomb", false, "Send parameters as usual, but don't attempt to identify/report valid ones. Useful for OAST techniques.");
        guessSettings.register("try cache poison", true, "After discovering a parameter, test whether it can be used for cache poisoning");
        guessSettings.register("twitchy cache poison", false, "Make cache poisoning detection capable of detecting non-reflected input (but more prone to FPs)");
        guessSettings.register("identify smuggle mutations", false, "Try using desync-style mutations to bypass header rewriting by front-ends.");
        guessSettings.register("try -_ bypass", false, "Convert all instances of - to _ in header names, to bypass some front-end rewrites");
        guessSettings.register("rotation interval", 999, "This doesn't work");
        guessSettings.register("rotation increment", 4, "This doesn't work");
        guessSettings.register("force bucketsize", -1, "Specify the number of parameters allowed in a single request. Set this to -1 to let Param Miner automatically determine this value on a per-target basis.");
        guessSettings.register("max bucketsize", 65536, "Maximum number of parameters Param Miner will consider putting in a single request if the server allows it.");
        guessSettings.register("max param length", 32, "This is used alongside the bucketsize detection");
        guessSettings.register("lowercase headers", true, "Send header names in lowercase. Good for efficiency.");
        guessSettings.register("name in issue", false, "Include the parameter name in the issue title");
        guessSettings.register("canary", "zwrtxqva", "Fixed prefix used to detect input reflection");
        guessSettings.register("force canary", "", "Use this to override the canary - useful with carpet bomb mode");
        guessSettings.register("poison only", false, "Don't report parameters if you can't use them for cache poisoning");
        guessSettings.register("tunnelling retry count", 20, "When attempting to mine a tunelled request, give up after this many consecutive failures to get a nested response");
        guessSettings.register("abort on tunnel failure", true, "When attempting to mine a tunelled request, give up if the tunnel retry count is exceeded");
        guessSettings.register("baseline size", 4, "Number of requests sent to build the normal-response fingerprint");

        loadWordlists();
        BlockingQueue<Runnable> tasks;
        if (BulkUtilities.globalSettings.getBoolean("enable auto-mine")) {
            tasks = new PriorityBlockingQueue<>(1000, new RandomComparator());
        }
        else {
            tasks = new LinkedBlockingQueue<>();
        }

        BulkUtilities.globalSettings.registerSetting("thread pool size", 8);
        taskEngine = new ThreadPoolExecutor(BulkUtilities.globalSettings.getInt("thread pool size"), BulkUtilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        BulkUtilities.globalSettings.registerListener("thread pool size", value -> {
            BulkUtilities.out("Updating active thread pool size to "+value);
            try {
                taskEngine.setCorePoolSize(Integer.parseInt(value));
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
            } catch (IllegalArgumentException e) {
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
                taskEngine.setCorePoolSize(Integer.parseInt(value));
            }
        });

        callbacks.setExtensionName(name);

        try {
            StringUtils.isNumeric("1");
        } catch (java.lang.NoClassDefFoundError e) {
            BulkUtilities.out("Failed to import the Apache Commons Lang library. You can get it from http://commons.apache.org/proper/commons-lang/");
            throw new NoClassDefFoundError();
        }

        try {
            callbacks.getHelpers().analyzeResponseVariations();
        } catch (java.lang.NoSuchMethodError e) {
            BulkUtilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
            throw new NoSuchMethodError();
        }

        paramGrabber = new ParamGrabber(taskEngine);
        //allbacks.registerContextMenuFactory(new OfferParamGuess(callbacks, paramGrabber, taskEngine));

        if(BulkUtilities.isBurpPro()) {
            callbacks.registerScannerCheck(new GrabScan(paramGrabber));
        }

        callbacks.registerHttpListener(paramGrabber);
        callbacks.registerProxyListener(paramGrabber);

        SwingUtilities.invokeLater(new ConfigMenu());

        new HeaderGuessScan("Guess headers");
        new URLGuessScan("Guess query params");
        new CookieGuessScan("Guess cookies");
        new BodyGuessScan("Guess body params");
        new EverythingGuessScan("Guess everything!");
        new Lenscrack("Detect scoped-SSRF");
        new Lensmine("Exploit scoped-SSRF");
        new TimeInjector("Detect server-side injection");
        new PortDOS("port-DoS");
        //new ValueScan("param-value probe");
        new UnkeyedParamScan("Unkeyed param");
        new FatGet("fat GET");
        new InputTransformationParamScan("input transformation");
        new NormalisedParamScan("normalised param");
        new NormalisedPathScan("normalised path");
        new RailsUtmScan("rails param cloaking scan");
        new HeaderMutationScan("identify header smuggling mutations");


        new BulkScanLauncher(BulkScan.scans);

        BulkUtilities.callbacks.registerExtensionStateListener(this);

        BulkUtilities.out("Loaded " + name + " v" + version);
    }

    private void loadWordlist(String name, Collection<String> fillme) {
        Scanner s = new Scanner(getClass().getResourceAsStream(name));
        while (s.hasNext()) {
            fillme.add(s.next());
        }
        s.close();
    }

    private void loadWordlists() {
        loadWordlist("/functions", BulkUtilities.phpFunctions);
        loadWordlist("/params", BulkUtilities.paramNames);
        loadWordlist("/boring_headers", BulkUtilities.boringHeaders);
        loadWordlist("/wafparams", BulkUtilities.wafParams);
    }

    public void extensionUnloaded() {
        BulkUtilities.log("Aborting all attacks");
        BulkUtilities.unloaded.set(true);
        taskEngine.getQueue().clear();
        taskEngine.shutdown();
    }

}





class RequestWithOffsets {
    private byte[] request;
    private int[] offsets;

    public RequestWithOffsets(byte[] request, int[] offsets) {
        this.request = request;
        this.offsets = offsets;
    }
}

class ParamNameInsertionPoint extends ParamInsertionPoint {
    String attackID;
    String defaultPrefix;
    String host;

    String collab;
    HashMap<String, String> present;

    ParamNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type);
        this.attackID = attackID;
        this.collab = "oastify.com";//BulkUtilities.getSetting("location"); // fixme should use configured server

        ArrayList<String> keys = Keysmith.getAllKeys(request, new HashMap<>());
        HashMap<String, Integer> freq = new HashMap<>();
        for (String key: keys) {
            if (key.contains(":")) {
                String object = key.split(":")[0];
                freq.put(object, freq.getOrDefault(object, 0) + 1);
            }
        }

        String maxKey = null;

        if (BulkUtilities.globalSettings.getBoolean("auto-nest params")) {
            int max = 0;
            for (Map.Entry<String, Integer> entry : freq.entrySet()) {
                if (entry.getValue() > max) {
                    maxKey = entry.getKey();
                    max = entry.getValue();
                }
            }
        }
        defaultPrefix = maxKey;

        if (maxKey != null) {
            BulkUtilities.out("Selected default key: "+maxKey);
        }
        else {
            BulkUtilities.log("No default key available");
        }

        present = new HashMap<>();
        List<String> headers = BulkUtilities.analyzeRequest(request).getHeaders();
        for (String header: headers) {
            if (header.startsWith("Host: ")) {
                host = header.split(": ", 2)[1];
            }
            header = header.split(": ", 2)[0];
            if (BulkUtilities.globalSettings.getBoolean("lowercase headers")) {
                present.put(header.toLowerCase(), header);
            }
            else {
                present.put(header, header);
            }
        }
    }

    String calculateValue(String unparsed) {
        String canary = BulkUtilities.globalSettings.getString("force canary");
        if (!"".equals(canary)) {
            return canary;
        }
        return BulkUtilities.toCanary(unparsed) + attackID + value + BulkUtilities.randomString(5) + BulkUtilities.fuzzSuffix();
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        String bulk = BulkUtilities.helpers.bytesToString(payload);
        String[] params = bulk.split("[|]");
        ArrayList<String> preppedParams = new ArrayList<>();
        for(String key: params) {
            if (defaultPrefix != null && !key.contains(":")) {
                key = defaultPrefix + ":" + key;
            }
            preppedParams.add(Keysmith.unparseParam(key));
        }

        if(type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_COOKIE || type == BulkUtilities.PARAM_HEADER) {
            return buildBulkRequest(preppedParams);
        }

        return buildBasicRequest(preppedParams);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        String replaceKey = "TCZqBcS13SA8QRCpW";
        IParameter newParam = BulkUtilities.helpers.buildParameter(replaceKey, "", type);
        byte[] built = BulkUtilities.helpers.updateParameter(request, newParam);
        return BulkUtilities.fixContentLength(BulkUtilities.replace(built, BulkUtilities.helpers.stringToBytes(replaceKey+"="), BulkUtilities.helpers.stringToBytes(merged)));
    }

    String prepBulkParams(ArrayList<String> params) {
        ArrayList<String> preppedParams = new ArrayList<>();

        String equals;
        String join;
        String trail;
        if(type == IParameter.PARAM_COOKIE) {
            equals = "=";
            join = "; ";
            trail = ";";
        }
        else if (type == BulkUtilities.PARAM_HEADER) {
            equals = ": ";
            join ="\r\n";
            trail = ""; // \r\n
        }
        else {
            equals = "=";
            join = "&";
            trail = "";
        }


        for (String param: params) {
            String fullParam[] = getValue(param);
            if ("".equals(fullParam[0])) {
                continue;
            }
            if (type == BulkUtilities.PARAM_HEADER) {
                preppedParams.add(fullParam[0] + equals + fullParam[1]);
            }
            else {
                preppedParams.add(BulkUtilities.encodeParam(fullParam[0]) + equals + BulkUtilities.encodeParam(fullParam[1]));
            }
        }

        return String.join(join, preppedParams) + trail;
    }

    String[] getValue(String name) {
        if (name.contains("~")) {
            String[] parts = name.split("~", 2);
            parts[1] = parts[1].replace("%s", calculateValue(name));
            parts[1] = parts[1].replace("%h", host);
            parts[1] = parts[1].replace("%c", collab);
            parts[1] = parts[1].replace("%r", BulkUtilities.generateCanary());
            return new String[]{parts[0], String.valueOf(BulkUtilities.invert(parts[1]))};
        }
        else {
            //return new String[]{name, } // todo collab goes here
            return new String[]{name, calculateValue(name)};
        }
    }

    byte[] buildBasicRequest(ArrayList<String> params) {
        byte[] built = request;
        for (String name: params) {
            String[] param = getValue(name);
            IParameter newParam = BulkUtilities.helpers.buildParameter(param[0], BulkUtilities.encodeParam(param[1]), type);
            built = BulkUtilities.helpers.updateParameter(built, newParam);
        }
        return built;
    }

    public RawInsertionPoint getValueInsertionPoint(String param) {
        String canary = BulkUtilities.generateCanary();
        param = param.split("~", 2)[0]+"~"+canary;

        byte[] dummyReq = buildRequest(param.getBytes());

        String payload = getValue(param)[1];
        byte[] scanBaseGrep = BulkUtilities.helpers.stringToBytes(canary);

        int start = BulkUtilities.helpers.indexOf(dummyReq, scanBaseGrep, true, 0, dummyReq.length);
        int end = start + scanBaseGrep.length;

        ArrayList<int[]> offsets = new ArrayList<>();
        offsets.add(new int[]{start, end});

        return new RawInsertionPoint(dummyReq, payload, start, end);
    }
}

class HeaderNameInsertionPoint extends ParamNameInsertionPoint {

    public HeaderNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type, attackID);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        Iterator<String> dupeCheck= params.iterator();
        byte[] body = BulkUtilities.getBodyBytes(request);

        boolean fooReq = false;
        if (BulkUtilities.containsBytes(body, "FOO BAR AAH\r\n".getBytes())) {
            fooReq = true;
        }

        if (fooReq || BulkUtilities.containsBytes(body, " HTTP/1.1\r\n".getBytes())) {
            BulkUtilities.chopNestedResponses = true;

            boolean usingCorrectContentLength = true;

            try {
                if (body.length != Integer.parseInt(BulkUtilities.getHeader(request, "Content-Length"))) {
                    usingCorrectContentLength = false;
                }
            } catch (Exception e) {

            }

            while (dupeCheck.hasNext()) {
                String param = dupeCheck.next().split("~", 2)[0];
                byte[] toReplace = ("\n"+param+": ").getBytes();
                if (BulkUtilities.containsBytes(body, toReplace)) {
                    body = BulkUtilities.replace(body, toReplace, ("\nold"+param+": ").getBytes());
                }
            }

            byte[] newBody;
            if (fooReq) {
                newBody = BulkUtilities.replaceFirst(body, "FOO BAR AAH\r\n", "GET http://"+BulkUtilities.getHeader(request, "Host")+"/ HTTP/1.1\r\n"+merged+"\r\n");
            }
            else {
                newBody = BulkUtilities.replaceFirst(body, "HTTP/1.1", "HTTP/1.1\r\n"+merged);
            }

            byte[] finalRequest = BulkUtilities.setBody(request, new String(newBody));
            if (usingCorrectContentLength) {
                finalRequest = BulkUtilities.fixContentLength(finalRequest);
            }

            finalRequest = BulkUtilities.addOrReplaceHeader(finalRequest, "X-Mine-Nested-Request", "1");

            return finalRequest;
        }

        String replaceKey = "TCZqBcS13SA8QRCpW";
        byte[] built = BulkUtilities.addOrReplaceHeader(request, replaceKey, "foo");

        if (params.isEmpty() || "".equals(merged)) {
            return built;
        }

        while (dupeCheck.hasNext()) {
            String param = dupeCheck.next().split("~", 2)[0];
            if (present.containsKey(param)) {
                String toReplace = present.get(param)+": ";
                built = BulkUtilities.replace(built, toReplace.getBytes(), ("old"+toReplace).getBytes());
            }
        }

        return BulkUtilities.setHeader(built, replaceKey, "x\r\n"+merged);
    }
}

class JsonParamNameInsertionPoint extends ParamNameInsertionPoint {
    byte[] headers;
    byte[] body;
    String baseInput;
    String attackID;
    JsonElement root;

    public JsonParamNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type, attackID);
        int start = BulkUtilities.getBodyStart(request);
        this.attackID = attackID;
        headers = Arrays.copyOfRange(request, 0, start);
        body = Arrays.copyOfRange(request, start, request.length);
        baseInput = BulkUtilities.helpers.bytesToString(body);
        root = new JsonParser().parse(baseInput);
    }

    private Object makeNode(ArrayList<String> keys, int i, Object paramValue) {
        if (i+1 == keys.size()) {
            return paramValue;
        }
        else if (BulkUtilities.parseArrayIndex(keys.get(i+1)) != -1) {
            return new ArrayList(BulkUtilities.parseArrayIndex(keys.get(i+1)));
        }
        else {
            return new HashMap();
        }
    }

    String calculateValue(String unparsed) {
        return BulkUtilities.toCanary(unparsed) + attackID + value + BulkUtilities.fuzzSuffix();
    }


    @Override
    @SuppressWarnings("unchecked")
    public byte[] buildRequest(byte[] payload) throws RuntimeException {
        String[] params = BulkUtilities.helpers.bytesToString(payload).split("[|]");
        String lastBuild = baseInput;

        try {
            for (String unparsed: params) {

                Object paramValue;
                if (unparsed.contains("~")) {
                    String[] parts = unparsed.split("~", 2);
                    unparsed = parts[0];
                    paramValue = BulkUtilities.invert(parts[1]);
                } else {
                    paramValue = calculateValue(unparsed);
                }

                ArrayList<String> keys = new ArrayList<>(Arrays.asList(unparsed.split(":")));

                boolean isArray = BulkUtilities.parseArrayIndex(keys.get(0)) != -1;
                Object base;
                if (isArray) {
                    try {
                        base = new ObjectMapper().readValue(lastBuild, ArrayList.class);
                    }
                    catch (MismatchedInputException e) {
                        base = new ArrayList();
                    }
                } else {
                    try {
                        base = new ObjectMapper().readValue(lastBuild, HashMap.class);
                    }
                    catch (MismatchedInputException e) {
                        base = new HashMap();
                    }
                }

                Object next = base;
                for (int i = 0; i < keys.size(); i++) {

                    try {
                        String key = keys.get(i);
                        boolean setValue = i + 1 == keys.size();

                        int index = BulkUtilities.parseArrayIndex(key);
                        if (index != -1) {
                            ArrayList injectionPoint = (ArrayList) next;
                            if (injectionPoint.size() < index + 1) {
                                for (int k = injectionPoint.size(); k < index; k++) {
                                    injectionPoint.add(BulkUtilities.generateCanary());
                                }
                                injectionPoint.add(makeNode(keys, i, paramValue));
                            } else if (injectionPoint.get(index) == null || setValue) {
                                injectionPoint.set(index, makeNode(keys, i, paramValue));
                            }
                            next = injectionPoint.get(index);
                        } else {
                            HashMap injectionPoint = (HashMap) next;
                            if (!injectionPoint.containsKey(key) || setValue) {
                                injectionPoint.put(key, makeNode(keys, i, paramValue));
                            }
                            next = injectionPoint.get(key);
                        }
                    } catch(ClassCastException e) {
                        //BulkUtilities.out("Cast error"); // todo figure out a sensible action to stop this form occuring
                    }
                }

                lastBuild = new ObjectMapper().writeValueAsString(base);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(headers);
            outputStream.write(BulkUtilities.helpers.stringToBytes(lastBuild));
            return BulkUtilities.fixContentLength(outputStream.toByteArray());
        } catch (Exception e) {
            BulkUtilities.out("Error with " + String.join(":", params));
            e.printStackTrace(new PrintStream(BulkUtilities.callbacks.getStdout()));
            return buildRequest(BulkUtilities.helpers.stringToBytes("error_" + String.join(":", params).replace(":", "_")));
            // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
        }
    }
}





