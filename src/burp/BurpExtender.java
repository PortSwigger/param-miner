package burp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;




public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Param Miner";
    private static final String version = "1.28";
    private ThreadPoolExecutor taskEngine;
    static ParamGrabber paramGrabber;
    static SettingsBox configSettings = new SettingsBox();
    static SettingsBox guessSettings = new SettingsBox();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks, new HashMap<>(), name);

        // config only (currently param-guess displays everything)
        configSettings.register("Add 'fcbz' cachebuster", false);
        configSettings.register("Add dynamic cachebuster", false);
        configSettings.register("Add header cachebuster", false);
        configSettings.register("learn observed words", false);
        configSettings.register("enable auto-mine", false);
        configSettings.register("auto-mine headers", false);
        configSettings.register("auto-mine cookies", false);
        configSettings.register("auto-mine params", false);
        configSettings.register("auto-nest params", false);

        // param-guess only
        //guessSettings.importSettings(globalSettings);
        guessSettings.register("learn observed words", false);
        guessSettings.register("skip boring words", true);
        guessSettings.register("only report unique params", false);
        guessSettings.register("response", true);
        guessSettings.register("request", true);
        guessSettings.register("use basic wordlist", true);
        guessSettings.register("use bonus wordlist", false);
        guessSettings.register("use assetnote params", false);
        guessSettings.register("use custom wordlist", false);
        guessSettings.register("custom wordlist path", "/usr/share/dict/words");
        guessSettings.register("bruteforce", false);
        guessSettings.register("skip uncacheable", false);
        guessSettings.register("dynamic keyload", false);
        guessSettings.register("max one per host", false);
        guessSettings.register("max one per host+status", false);
        guessSettings.register("probe identified params", true);
        guessSettings.register("scan identified params", false);
        guessSettings.register("fuzz detect", false);
        guessSettings.register("carpet bomb", false);
        guessSettings.register("try cache poison", true);
        guessSettings.register("twitchy cache poison", false);
        guessSettings.register("try method flip", false);
        guessSettings.register("try -_ bypass", false);
        guessSettings.register("rotation interval", 200);
        guessSettings.register("rotation increment", 4);
        guessSettings.register("force bucketsize", -1);
        guessSettings.register("max bucketsize", 65536);
        guessSettings.register("max param length", 32);
        guessSettings.register("lowercase headers", true);
        guessSettings.register("name in issue", false);
        guessSettings.register("canary", "zwrtxqva");
        guessSettings.register("force canary", "");
        guessSettings.register("poison only", false);
        guessSettings.register("tunnelling retry count", 20);
        guessSettings.register("abort on tunnel failure", true);


        loadWordlists();
        BlockingQueue<Runnable> tasks;
        if (Utilities.globalSettings.getBoolean("enable auto-mine")) {
            tasks = new PriorityBlockingQueue<>(1000, new RandomComparator());
        }
        else {
            tasks = new LinkedBlockingQueue<>();
        }

        Utilities.globalSettings.registerSetting("thread pool size", 8);
        taskEngine = new ThreadPoolExecutor(Utilities.globalSettings.getInt("thread pool size"), Utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        Utilities.globalSettings.registerListener("thread pool size", value -> {
            Utilities.out("Updating active thread pool size to "+value);
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
            Utilities.out("Failed to import the Apache Commons Lang library. You can get it from http://commons.apache.org/proper/commons-lang/");
            throw new NoClassDefFoundError();
        }

        try {
            callbacks.getHelpers().analyzeResponseVariations();
        } catch (java.lang.NoSuchMethodError e) {
            Utilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
            throw new NoSuchMethodError();
        }

        paramGrabber = new ParamGrabber(taskEngine);
        callbacks.registerContextMenuFactory(new OfferParamGuess(callbacks, paramGrabber, taskEngine));

        if(Utilities.isBurpPro()) {
            callbacks.registerScannerCheck(new GrabScan(paramGrabber));
        }

        callbacks.registerHttpListener(paramGrabber);
        callbacks.registerProxyListener(paramGrabber);

        SwingUtilities.invokeLater(new ConfigMenu());

        new HeaderPoison("Header poison");
        new PortDOS("port-DoS");
        //new ValueScan("param-value probe");
        new UnkeyedParamScan("Unkeyed param");
        new FatGet("fat GET");
        new NormalisedParamScan("normalised param");
        new NormalisedPathScan("normalised path");
        new RailsUtmScan("rails param cloaking scan");


        new BulkScanLauncher(BulkScan.scans);

        Utilities.callbacks.registerExtensionStateListener(this);

        Utilities.out("Loaded " + name + " v" + version);
    }


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
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
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

class ParamInsertionPoint implements IScannerInsertionPoint {
    byte[] request;
    String name;
    String value;
    byte type;

    ParamInsertionPoint(byte[] request, String name, String value, byte type) {
        this.request = request;
        this.name = name;
        this.value = value;
        this.type = type;
    }

    String calculateValue(String unparsed) {
        return unparsed;
    }

    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public String getBaseValue() {
        return value;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        IParameter newParam = Utilities.helpers.buildParameter(name, Utilities.encodeParam(Utilities.helpers.bytesToString(payload)), type);
        return Utilities.helpers.updateParameter(request, newParam);
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        //IParameter newParam = Utilities.helpers.buildParameter(name, Utilities.encodeParam(Utilities.helpers.bytesToString(payload)), type);
        return new int[]{0, 0};
        //return new int[]{newParam.getValueStart(), newParam.getValueEnd()};
    }

    @Override
    public byte getInsertionPointType() {
        return type;
        //return IScannerInsertionPoint.INS_PARAM_BODY;
        // return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}

class ParamNameInsertionPoint extends ParamInsertionPoint {
    String attackID;
    String defaultPrefix;
    String host;
    HashMap<String, String> present;

    ParamNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type);
        this.attackID = attackID;

        ArrayList<String> keys = Keysmith.getAllKeys(request, new HashMap<>());
        HashMap<String, Integer> freq = new HashMap<>();
        for (String key: keys) {
            if (key.contains(":")) {
                String object = key.split(":")[0];
                freq.put(object, freq.getOrDefault(object, 0) + 1);
            }
        }

        String maxKey = null;

        if (Utilities.globalSettings.getBoolean("auto-nest params")) {
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
            Utilities.out("Selected default key: "+maxKey);
        }
        else {
            Utilities.log("No default key available");
        }

        present = new HashMap<>();
        List<String> headers = Utilities.analyzeRequest(request).getHeaders();
        for (String header: headers) {
            if (header.startsWith("Host: ")) {
                host = header.split(": ", 2)[1];
            }
            header = header.split(": ", 2)[0];
            if (Utilities.globalSettings.getBoolean("lowercase headers")) {
                present.put(header.toLowerCase(), header);
            }
            else {
                present.put(header, header);
            }
        }
    }

    String calculateValue(String unparsed) {
        String canary = Utilities.globalSettings.getString("force canary");
        if (!"".equals(canary)) {
            return canary;
        }
        return Utilities.toCanary(unparsed) + attackID + value + Utilities.fuzzSuffix();
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        String bulk = Utilities.helpers.bytesToString(payload);
        String[] params = bulk.split("[|]");
        ArrayList<String> preppedParams = new ArrayList<>();
        for(String key: params) {
            if (defaultPrefix != null && !key.contains(":")) {
                key = defaultPrefix + ":" + key;
            }
            preppedParams.add(Keysmith.unparseParam(key));
        }

        if(type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_COOKIE || type == Utilities.PARAM_HEADER) {
            return buildBulkRequest(preppedParams);
        }

        return buildBasicRequest(preppedParams);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        String replaceKey = "TCZqBcS13SA8QRCpW";
        IParameter newParam = Utilities.helpers.buildParameter(replaceKey, "", type);
        byte[] built = Utilities.helpers.updateParameter(request, newParam);
        return Utilities.fixContentLength(Utilities.replace(built, Utilities.helpers.stringToBytes(replaceKey+"="), Utilities.helpers.stringToBytes(merged)));
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
        else if (type == Utilities.PARAM_HEADER) {
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
            if (type == Utilities.PARAM_HEADER) {
                preppedParams.add(fullParam[0] + equals + fullParam[1]);
            }
            else {
                preppedParams.add(Utilities.encodeParam(fullParam[0]) + equals + Utilities.encodeParam(fullParam[1]));
            }
        }

        return String.join(join, preppedParams) + trail;
    }

    String[] getValue(String name) {
        if (name.contains("~")) {
            String[] parts = name.split("~", 2);
            parts[1] = parts[1].replace("%s", calculateValue(name));
            parts[1] = parts[1].replace("%h", host);
            return new String[]{parts[0], String.valueOf(Utilities.invert(parts[1]))};
        }
        else {
            return new String[]{name, calculateValue(name)};
        }
    }

    byte[] buildBasicRequest(ArrayList<String> params) {
        byte[] built = request;
        for (String name: params) {
            String[] param = getValue(name);
            IParameter newParam = Utilities.helpers.buildParameter(param[0], Utilities.encodeParam(param[1]), type);
            built = Utilities.helpers.updateParameter(built, newParam);
        }
        return built;
    }
}

class HeaderNameInsertionPoint extends ParamNameInsertionPoint {

    public HeaderNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type, attackID);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        Iterator<String> dupeCheck= params.iterator();
        byte[] body = Utilities.getBodyBytes(request);

        boolean fooReq = false;
        if (Utilities.containsBytes(body, "FOO BAR AAH\r\n".getBytes())) {
            fooReq = true;
        }

        if (fooReq || Utilities.containsBytes(body, " HTTP/1.1\r\n".getBytes())) {
            Utilities.chopNestedResponses = true;

            boolean usingCorrectContentLength = true;

            try {
                if (body.length != Integer.parseInt(Utilities.getHeader(request, "Content-Length"))) {
                    usingCorrectContentLength = false;
                }
            } catch (Exception e) {

            }

            while (dupeCheck.hasNext()) {
                String param = dupeCheck.next().split("~", 2)[0];
                byte[] toReplace = ("\n"+param+": ").getBytes();
                if (Utilities.containsBytes(body, toReplace)) {
                    body = Utilities.replace(body, toReplace, ("\nold"+param+": ").getBytes());
                }
            }

            byte[] newBody;
            if (fooReq) {
                newBody = Utilities.replaceFirst(body, "FOO BAR AAH\r\n", "GET http://"+Utilities.getHeader(request, "Host")+"/ HTTP/1.1\r\n"+merged+"\r\n");
            }
            else {
                newBody = Utilities.replaceFirst(body, "HTTP/1.1", "HTTP/1.1\r\n"+merged);
            }

            byte[] finalRequest = Utilities.setBody(request, new String(newBody));
            if (usingCorrectContentLength) {
                finalRequest = Utilities.fixContentLength(finalRequest);
            }

            finalRequest = Utilities.addOrReplaceHeader(finalRequest, "X-Mine-Nested-Request", "1");

            return finalRequest;
        }

        String replaceKey = "TCZqBcS13SA8QRCpW";
        byte[] built = Utilities.addOrReplaceHeader(request, replaceKey, "foo");

        if (params.isEmpty() || "".equals(merged)) {
            return built;
        }

        while (dupeCheck.hasNext()) {
            String param = dupeCheck.next().split("~", 2)[0];
            if (present.containsKey(param)) {
                String toReplace = present.get(param)+": ";
                built = Utilities.replace(built, toReplace.getBytes(), ("old"+toReplace).getBytes());
            }
        }

        return Utilities.setHeader(built, replaceKey, "x\r\n"+merged);
    }
}

class JsonParamNameInsertionPoint extends ParamInsertionPoint {
    byte[] headers;
    byte[] body;
    String baseInput;
    String attackID;
    JsonElement root;

    public JsonParamNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type); // Utilities.encodeJSON(value)
        int start = Utilities.getBodyStart(request);
        this.attackID = attackID;
        headers = Arrays.copyOfRange(request, 0, start);
        body = Arrays.copyOfRange(request, start, request.length);
        baseInput = Utilities.helpers.bytesToString(body);
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

    String calculateValue(String unparsed) {
        return Utilities.toCanary(unparsed) + attackID + value + Utilities.fuzzSuffix();
    }


    @Override
    @SuppressWarnings("unchecked")
    public byte[] buildRequest(byte[] payload) throws RuntimeException {
        String[] params = Utilities.helpers.bytesToString(payload).split("[|]");
        String lastBuild = baseInput;

        try {
            for (String unparsed: params) {

                Object paramValue;
                if (unparsed.contains("~")) {
                    String[] parts = unparsed.split("~", 2);
                    unparsed = parts[0];
                    paramValue = Utilities.invert(parts[1]);
                } else {
                    paramValue = calculateValue(unparsed);
                }

                ArrayList<String> keys = new ArrayList<>(Arrays.asList(unparsed.split(":")));

                boolean isArray = Utilities.parseArrayIndex(keys.get(0)) != -1;
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

                        int index = Utilities.parseArrayIndex(key);
                        if (index != -1) {
                            ArrayList injectionPoint = (ArrayList) next;
                            if (injectionPoint.size() < index + 1) {
                                for (int k = injectionPoint.size(); k < index; k++) {
                                    injectionPoint.add(Utilities.generateCanary());
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
                        //Utilities.out("Cast error"); // todo figure out a sensible action to stop this form occuring
                    }
                }

                lastBuild = new ObjectMapper().writeValueAsString(base);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(headers);
            outputStream.write(Utilities.helpers.stringToBytes(lastBuild));
            return Utilities.fixContentLength(outputStream.toByteArray());
        } catch (Exception e) {
            Utilities.out("Error with " + String.join(":", params));
            e.printStackTrace(new PrintStream(Utilities.callbacks.getStdout()));
            return buildRequest(Utilities.helpers.stringToBytes("error_" + String.join(":", params).replace(":", "_")));
            // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
        }
    }
}






