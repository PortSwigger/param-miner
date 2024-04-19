package burp;

import burp.model.header.HeaderMutationScan;
import burp.model.header.HeaderPoison;
import burp.model.scanning.BulkScan;
import burp.model.scanning.BulkScanLauncher;
import burp.model.utilities.Utilities;
import burp.view.ConfigMenu;
import burp.albinowaxUtils.ParamInsertionPoint;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import burp.view.SettingsBox;
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
    private static final String version = "1.4f";
private       ThreadPoolExecutor taskEngine;
public static ParamGrabber       paramGrabber;
static        SettingsBox        configSettings;
public static SettingsBox guessSettings;

    @Override
    public void initialize(MontoyaApi montoyaApi) {

    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        utilities      = new Utilities(callbacks, new HashMap<>(), name);
        configSettings = new SettingsBox(utilities);
        guessSettings  = new SettingsBox(utilities);

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
        guessSettings.register("learn observed words", false);
        guessSettings.register("skip boring words", true, "When mining headers, don't check for well known and typically not very exciting headers");
        guessSettings.register("only report unique params", false, "Only report a parameter with a given name once, regardless of how many endpoints are scanned");
        guessSettings.register("response", true, "Extract words from the target request, and use these to guess params");
        guessSettings.register("request", true, "Extract words from the target response, and use these to guess params. Highly recommended.");
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
        guessSettings.register("try method flip", false, "Try flipping GET to POST to fit more parameters in each request");
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
      
        loadWordlists();
        BlockingQueue<Runnable> tasks;
        if (utilities.globalSettings.getBoolean("enable auto-mine")) {
            tasks = new PriorityBlockingQueue<>(1000, new RandomComparator());
        }
        else {
            tasks = new LinkedBlockingQueue<>();
        }

        utilities.globalSettings.registerSetting("thread pool size", 8);
        taskEngine = new ThreadPoolExecutor(utilities.globalSettings.getInt("thread pool size"), utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        utilities.globalSettings.registerListener("thread pool size", value -> {
            utilities.out("Updating active thread pool size to "+value);
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
        } catch (NoClassDefFoundError e) {
            utilities.out("Failed to import the Apache Commons Lang library. You can get it from http://commons.apache.org/proper/commons-lang/");
            throw new NoClassDefFoundError();
        }

        try {
            callbacks.getHelpers().analyzeResponseVariations();
        } catch (NoSuchMethodError e) {
            utilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
            throw new NoSuchMethodError();
        }

        paramGrabber = new ParamGrabber(taskEngine, utilities);
        callbacks.registerContextMenuFactory(new OfferParamGuess(callbacks, paramGrabber, taskEngine, utilities));

        if(utilities.isBurpPro()) {
            callbacks.registerScannerCheck(new GrabScan(paramGrabber, utilities));
        }

        callbacks.registerHttpListener(paramGrabber);
        callbacks.registerProxyListener(paramGrabber);

        SwingUtilities.invokeLater(new ConfigMenu(utilities));
      
        BulkScanLauncher launcher = new BulkScanLauncher(BulkScan.scans, utilities);
        
        new HeaderPoison("Header poison", utilities, launcher);
        new PortDOS("port-DoS", utilities, launcher);
        //new ValueScan("param-value probe");
        new UnkeyedParamScan("Unkeyed param", utilities, launcher);
        new FatGet("fat GET", utilities, launcher);
        new NormalisedParamScan("normalised param", utilities, launcher);
        new NormalisedPathScan("normalised path", utilities, launcher);
        new RailsUtmScan("rails param cloaking scan", utilities, launcher);
        new HeaderMutationScan("identify header smuggling mutations", utilities, launcher);
      
      
      
      utilities.callbacks.registerExtensionStateListener(this);

        utilities.out("Loaded " + name + " v" + version);
    }

private Utilities utilities;

private void loadWordlists() {
        Scanner s = new Scanner(getClass().getResourceAsStream("/functions"));
        while (s.hasNext()) {
            Utilities.phpFunctions.add(s.next());
        }
        s.close();

        Scanner params = new Scanner(getClass().getResourceAsStream("/params"));
        while (params.hasNext()) {
            Utilities.paramNames.add(params.next());
        }
        params.close();

        Scanner headers = new Scanner(getClass().getResourceAsStream("/boring_headers"));
        while (headers.hasNext()) {
            Utilities.boringHeaders.add(headers.next().toLowerCase());
        }
    }

    public void extensionUnloaded() {
        utilities.log("Aborting all attacks");
        utilities.unloaded.set(true);
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

class HeaderNameInsertionPoint extends ParamNameInsertionPoint {

    public HeaderNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID, Utilities utilities) {
        super(request, name, value, type, attackID, utilities);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        Iterator<String> dupeCheck= params.iterator();
        byte[] body = utilities.getBodyBytes(request);

        boolean fooReq = false;
        if (utilities.containsBytes(body, "FOO BAR AAH\r\n".getBytes())) {
            fooReq = true;
        }

        if (fooReq || utilities.containsBytes(body, " HTTP/1.1\r\n".getBytes())) {
            utilities.chopNestedResponses = true;

            boolean usingCorrectContentLength = true;

            try {
                if (body.length != Integer.parseInt(utilities.getHeader(request, "Content-Length"))) {
                    usingCorrectContentLength = false;
                }
            } catch (Exception e) {

            }

            while (dupeCheck.hasNext()) {
                String param = dupeCheck.next().split("~", 2)[0];
                byte[] toReplace = ("\n"+param+": ").getBytes();
                if (utilities.containsBytes(body, toReplace)) {
                    body = utilities.replace(body, toReplace, ("\nold"+param+": ").getBytes());
                }
            }

            byte[] newBody;
            if (fooReq) {
                newBody = utilities.replaceFirst(body, "FOO BAR AAH\r\n", "GET http://"+utilities.getHeader(request, "Host")+"/ HTTP/1.1\r\n"+merged+"\r\n");
            }
            else {
                newBody = utilities.replaceFirst(body, "HTTP/1.1", "HTTP/1.1\r\n"+merged);
            }

            byte[] finalRequest = utilities.setBody(request, new String(newBody));
            if (usingCorrectContentLength) {
                finalRequest = Utilities.fixContentLength(finalRequest);
            }

            finalRequest = utilities.addOrReplaceHeader(finalRequest, "X-Mine-Nested-Request", "1");

            return finalRequest;
        }

        String replaceKey = "TCZqBcS13SA8QRCpW";
        byte[] built = utilities.addOrReplaceHeader(request, replaceKey, "foo");

        if (params.isEmpty() || "".equals(merged)) {
            return built;
        }

        while (dupeCheck.hasNext()) {
            String param = dupeCheck.next().split("~", 2)[0];
            if (present.containsKey(param)) {
                String toReplace = present.get(param)+": ";
                built = utilities.replace(built, toReplace.getBytes(), ("old"+toReplace).getBytes());
            }
        }

        return utilities.setHeader(built, replaceKey, "x\r\n"+merged);
    }
}

class JsonParamNameInsertionPoint extends ParamInsertionPoint {
    byte[] headers;
    byte[] body;
    String baseInput;
    String attackID;
    JsonElement root;

    public JsonParamNameInsertionPoint(
      byte[] request, String name, String value, byte type, String attackID, Utilities utilities
    ) {
        super(request, name, value, type, utilities); // utilities.encodeJSON(value)
        int start = Utilities.getBodyStart(request);
        this.attackID = attackID;
        headers = Arrays.copyOfRange(request, 0, start);
        body = Arrays.copyOfRange(request, start, request.length);
        baseInput = utilities.helpers.bytesToString(body);
        root = new JsonParser().parse(baseInput);
    }

    private Object makeNode(ArrayList<String> keys, int i, Object paramValue) {
        if (i+1 == keys.size()) {
            return paramValue;
        }
        else if (Utilities.parseArrayIndex(keys.get(i+1)) != -1) {
            return new ArrayList(Utilities.parseArrayIndex(keys.get(i+1)));
        }
        else {
            return new HashMap();
        }
    }

    public String calculateValue(String unparsed) {
        return utilities.toCanary(unparsed) + attackID + value + utilities.fuzzSuffix();
    }


    @Override
    @SuppressWarnings("unchecked")
    public byte[] buildRequest(byte[] payload) throws RuntimeException {
        String[] params = utilities.helpers.bytesToString(payload).split("[|]");
        String lastBuild = baseInput;

        try {
            for (String unparsed: params) {

                Object paramValue;
                if (unparsed.contains("~")) {
                    String[] parts = unparsed.split("~", 2);
                    unparsed = parts[0];
                    paramValue = utilities.invert(parts[1]);
                } else {
                    paramValue = calculateValue(unparsed);
                }

                ArrayList<String> keys = new ArrayList<>(Arrays.asList(unparsed.split(":")));

                boolean isArray = utilities.parseArrayIndex(keys.get(0)) != -1;
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

                        int index = utilities.parseArrayIndex(key);
                        if (index != -1) {
                            ArrayList injectionPoint = (ArrayList) next;
                            if (injectionPoint.size() < index + 1) {
                                for (int k = injectionPoint.size(); k < index; k++) {
                                    injectionPoint.add(utilities.generateCanary());
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
                        //utilities.out("Cast error"); // todo figure out a sensible action to stop this form occuring
                    }
                }

                lastBuild = new ObjectMapper().writeValueAsString(base);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(headers);
            outputStream.write(utilities.helpers.stringToBytes(lastBuild));
            return utilities.fixContentLength(outputStream.toByteArray());
        } catch (Exception e) {
            utilities.out("Error with " + String.join(":", params));
            e.printStackTrace(new PrintStream(utilities.callbacks.getStdout()));
            return buildRequest(utilities.helpers.stringToBytes("error_" + String.join(":", params).replace(":", "_")));
            // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
        }
    }
}






