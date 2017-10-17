package burp;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import org.apache.commons.lang3.StringEscapeUtils;

import org.apache.commons.lang3.StringUtils;

import static burp.Keysmith.getHtmlKeys;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Backslash Powered Scanner";
    private static final String version = "0.91";
    private ThreadPoolExecutor taskEngine;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        BlockingQueue<Runnable> tasks = new LinkedBlockingQueue<>();
        this.taskEngine = new ThreadPoolExecutor(5, 10, 10, TimeUnit.MINUTES, tasks);
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

        FastScan scan = new FastScan(callbacks);
        callbacks.registerScannerCheck(scan);
        callbacks.registerExtensionStateListener(scan);

        ParamGrabber paramGrabber = new ParamGrabber();
        callbacks.registerContextMenuFactory(new OfferParamGuess(callbacks, paramGrabber, taskEngine));
        callbacks.registerIntruderPayloadGeneratorFactory(new ParamSpammerFactory(paramGrabber));
        callbacks.registerScannerCheck(paramGrabber);

        Utilities.out("Loaded " + name + " v" + version);
        Utilities.out("Debug mode: " + Utilities.DEBUG);
        Utilities.out("Thorough mode: " + Utilities.THOROUGH_MODE);
        Utilities.out("Input transformation detection: " + Utilities.TRANSFORMATION_SCAN);
        Utilities.out("Suspicious input handling detection: " + Utilities.DIFFING_SCAN);
        Utilities.out("    TRY_SYNTAX_ATTACKS "+Utilities.TRY_SYNTAX_ATTACKS);
        Utilities.out("    TRY_VALUE_PRESERVING_ATTACKS "+Utilities.TRY_VALUE_PRESERVING_ATTACKS);
        Utilities.out("    TRY_EXPERIMENTAL_CONCAT_ATTACKS "+Utilities.TRY_EXPERIMENTAL_CONCAT_ATTACKS);
        Utilities.out("    TRY_HPP "+Utilities.TRY_HPP);
        Utilities.out("    TRY_HPP_FOLLOWUP "+Utilities.TRY_HPP_FOLLOWUP);
        Utilities.out("    TRY_MAGIC_VALUE_ATTACKS "+Utilities.TRY_MAGIC_VALUE_ATTACKS);

    }


}

class ParamSpammerFactory implements IIntruderPayloadGeneratorFactory {

    ParamGrabber grabber;

    public ParamSpammerFactory(ParamGrabber grabber) {
        this.grabber = grabber;
    }

    @Override
    public String getGeneratorName() {
        return "Observed Parameter Spammer";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        attack.getRequestTemplate();
        byte[] baseLine = attack.getRequestTemplate();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        //byte foo = (byte) 0xa7;
        for(byte b: baseLine) {
            if (b != (byte) 0xa7) { // §
                outputStream.write(b);
            }
        }
        baseLine = Utilities.fixContentLength(outputStream.toByteArray());
        IHttpRequestResponse req = Utilities.callbacks.makeHttpRequest(attack.getHttpService(), baseLine);
        ArrayList<String> params = ParamGuesser.calculatePayloads(req, IParameter.PARAM_BODY, grabber);
        return new ParamSpammer(params);
    }
}

class ParamSpammer implements IIntruderPayloadGenerator {

    private ArrayList<String> params;
    private int index = 0;

    public ParamSpammer(ArrayList<String> params) {
        this.params = params;
    }

    @Override
    public boolean hasMorePayloads() {
        return (params.size() > index+1);
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        return Utilities.helpers.stringToBytes(params.get(index++));
    }

    @Override
    public void reset() {
        index = 0;
    }
}

class ParamGrabber implements  IScannerCheck {

    public HashSet<JsonElement> getSavedJson() {
        return savedJson;
    }

    HashSet<JsonElement> savedJson;
    HashSet<ArrayList<String>> done;

    public HashSet<String> getSavedGET() {
        return savedGET;
    }

    HashSet<String> savedGET;

    ParamGrabber() {
        savedJson = new HashSet<>();
        done = new HashSet<>();
        savedGET = new HashSet<>();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        saveParams(baseRequestResponse);
        return new ArrayList<>();
    }

    public void saveParams(IHttpRequestResponse baseRequestResponse) {
        // todo also use observed requests
        String body = Utilities.getBody(baseRequestResponse.getResponse());
        if (!body.equals("")) {
            savedGET.addAll(getHtmlKeys(body));
            try {
                JsonParser parser = new JsonParser();
                JsonElement json = parser.parse(body);
                ArrayList<String> keys = Keysmith.getJsonKeys(json, new HashMap<>());
                if (!done.contains(keys)) {
                    //Utilities.out("Importing observed data...");
                    done.add(keys);
                    savedJson.add(json);
                }
            } catch (JsonParseException e) {

            }
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}

class FastScan implements IScannerCheck, IExtensionStateListener {
    private TransformationScan transformationScan;
    private DiffingScan diffingScan;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    FastScan(final IBurpExtenderCallbacks callbacks) {
        transformationScan = new TransformationScan(callbacks);
        diffingScan = new DiffingScan();
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    public void extensionUnloaded() {
        Utilities.out("Unloading extension...");
        Utilities.unloaded.set(true);
    }

    private IParameter getParameterFromInsertionPoint(IScannerInsertionPoint insertionPoint, byte[] request) {
        IParameter baseParam = null;
        int basePayloadStart = insertionPoint.getPayloadOffsets("x".getBytes())[0];
        List<IParameter> params = helpers.analyzeRequest(request).getParameters();
        for (IParameter param : params) {
            if (param.getValueStart() == basePayloadStart && insertionPoint.getBaseValue().equals(param.getValue())) {
                baseParam = param;
                break;
            }
        }
        return baseParam;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        ArrayList<IScanIssue> issues = new ArrayList<>();
        if(!(Utilities.TRANSFORMATION_SCAN || Utilities.DIFFING_SCAN)) {
            Utilities.out("Aborting scan - all scanner checks disabled");
            return issues;
        }

        // make a custom insertion point to avoid burp excessively URL-encoding payloads
        IParameter baseParam = getParameterFromInsertionPoint(insertionPoint, baseRequestResponse.getRequest());
        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL)) {
            insertionPoint = new ParamInsertionPoint(baseRequestResponse.getRequest(), baseParam.getName(), baseParam.getValue(), baseParam.getType());
        }

        if (Utilities.TRANSFORMATION_SCAN) {
            issues.add(transformationScan.findTransformationIssues(baseRequestResponse, insertionPoint));
        }

        if (Utilities.DIFFING_SCAN) {
            issues.add(diffingScan.findReflectionIssues(baseRequestResponse, insertionPoint));
        }

        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL) && Utilities.getExtension(baseRequestResponse.getRequest()).equals(".php")) {
            String param_name = baseParam.getName() + "[]";
            byte[] newReq = helpers.removeParameter(baseRequestResponse.getRequest(), baseParam);
            IParameter newParam = helpers.buildParameter(param_name, baseParam.getValue(), baseParam.getType());
            newReq = helpers.addParameter(newReq, helpers.buildParameter(param_name, "", baseParam.getType()));
            newReq = helpers.addParameter(newReq, newParam);

            IScannerInsertionPoint arrayInsertionPoint = new ParamInsertionPoint(newReq, param_name, newParam.getValue(), newParam.getType());
            IHttpRequestResponse newBase = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), arrayInsertionPoint.buildRequest(newParam.getValue().getBytes()));

            if (Utilities.TRANSFORMATION_SCAN) {
                issues.add(transformationScan.findTransformationIssues(newBase, arrayInsertionPoint));
            }

            if (Utilities.DIFFING_SCAN) {
                issues.add(diffingScan.findReflectionIssues(newBase, arrayInsertionPoint));
            }
        }

        return issues
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return new ArrayList<>();

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}


class Fuzzable extends CustomScanIssue {
    private final static String NAME = "Interesting input handling: ";
    private final static String DETAIL = "The application reacts to inputs in a way that suggests it might be vulnerable to some kind of server-side code injection. The probes are listed below in chronological order, with evidence. Response attributes that only stay consistent in one probe-set are italicised, with the variable attribute starred.";
    private final static String REMEDIATION = "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. Try to determine the root cause of the observed behaviour." +
            "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ";

    Fuzzable(IHttpRequestResponse[] requests, URL url, String title, String detail, boolean reliable, String severity) {
        super(requests[0].getHttpService(), url, requests, NAME + title, DETAIL + detail, severity, calculateConfidence(reliable), REMEDIATION);
    }

    private static String calculateConfidence(boolean reliable) {
        String confidence = "Tentative";
        if (reliable) {
            confidence = "Firm";
        }
        return confidence;
    }

}

class InputTransformation extends CustomScanIssue {
    private final static String NAME = "Suspicious input transformation";
    private final static String DETAIL = "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection";
    private final static String REMEDIATION =
            "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. " +
                    "Try to determine the root cause of the observed input transformations. " +
                    "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results.";
    private final static String CONFIDENCE = "Tentative";

    InputTransformation(ArrayList<String> interesting, ArrayList<String> boring, IHttpRequestResponse base, URL url, String paramName) {
        super(base.getHttpService(), url, new IHttpRequestResponse[]{base}, NAME, generateDetail(interesting, boring, paramName), generateSeverity(interesting), CONFIDENCE, REMEDIATION);
    }

    private static String generateSeverity(ArrayList<String> interesting) {
        String severity = "High";
        if (interesting.size() == 1 && interesting.contains("\\0 => \0")) {
            severity = "Information";
        }
        return severity;
    }

    private static String generateDetail(ArrayList<String> interesting, ArrayList<String> boring, String paramName) {
        String details = DETAIL + "<br/><br/>Affected parameter:<code>" + StringEscapeUtils.escapeHtml4(paramName) + "</code><br/><br/>";
        details += "<p>Interesting transformations:</p><ul> ";
        for (String transform : interesting) {
            details += "<li><b><code style='font-size: 125%;'>" + StringEscapeUtils.escapeHtml4(transform) + "</code></b></li>";
        }
        details += "</ul><p>Boring transformations:</p><ul>";
        for (String transform : boring) {
            details += "<li><b><code>" + StringEscapeUtils.escapeHtml4(transform) + "</code></b></li>";
        }
        details += "</ul>";
        return details;
    }
}

class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[1];
        this.httpMessages[0] = httpMessages;

        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
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

    ParamNameInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type);
        this.attackID = attackID;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        String name = Utilities.helpers.bytesToString(payload);
        String val = Utilities.toCanary(name) + attackID + value;
        IParameter newParam = Utilities.helpers.buildParameter(name, Utilities.encodeParam(val), type);
        return Utilities.helpers.updateParameter(request, newParam);
    }
}

class RailsInsertionPoint extends ParamNameInsertionPoint {
    String defaultPrefix;

    RailsInsertionPoint(byte[] request, String name, String value, byte type, String attackID) {
        super(request, name, value, type, attackID);
        ArrayList<String> keys = Keysmith.getAllKeys(request, new HashMap<>());
        HashMap<String, Integer> freq = new HashMap<>();
        for (String key: keys) {
            if (key.contains(":")) {
                String object = key.split(":")[0];
                freq.put(object, freq.getOrDefault(object, 0) + 1);
            }
        }

        String maxKey = null;
        int max = 0;
        for (Map.Entry<String, Integer> entry: freq.entrySet()) {
            if (entry.getValue() > max) {
                maxKey = entry.getKey();
                max = entry.getValue();
            }
        }
        defaultPrefix = maxKey;

        if (maxKey != null) {
            Utilities.out("Identified default key: "+maxKey);
        }
    }

    public byte[] buildRequest(byte[] payload) {
        String key = Utilities.helpers.bytesToString(payload);
        if (defaultPrefix != null && !key.contains(":")) {
            key = defaultPrefix + ":" + key;
        }
        return super.buildRequest(Utilities.helpers.stringToBytes(Keysmith.unparseParam(key)));
    }

}
/*class RailsInsertionPoint extends ParamInsertionPoint {
    byte[] headers;
    byte[] body;
    String baseInput;
    String mainObjectName;

    public RailsInsertionPoint(byte[] request, String name, String value, byte type) {
        super(request, name, value, type);
        int start = Utilities.getBodyStart(request);
        headers = Arrays.copyOfRange(request, 0, start);
        body = Arrays.copyOfRange(request, start, request.length);
        baseInput = Utilities.helpers.bytesToString(body);
    }

    public byte[] buildRequest(byte[] payload) throws RuntimeException {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(headers);
            outputStream.write(Utilities.helpers.stringToBytes(mergedJson));
            return Utilities.fixContentLength(outputStream.toByteArray());
        } catch (Exception e) {
            Utilities.out("Error with "+unparsed);
            e.printStackTrace(new PrintStream(Utilities.callbacks.getStdout()));
            return buildRequest(Utilities.helpers.stringToBytes("error_"+unparsed.replace(":", "_")));
            // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
        }

    }
}*/

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

    private Object makeNode(ArrayList<String> keys, int i, String unparsed) {
        if (i+1 == keys.size()) {
            return Utilities.toCanary(unparsed) + attackID + value;
        }
        else if (Utilities.parseArrayIndex(keys.get(i+1)) != -1) {
            return new ArrayList(Utilities.parseArrayIndex(keys.get(i+1)));
        }
        else {
            return new HashMap();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public byte[] buildRequest(byte[] payload) throws RuntimeException {
        String unparsed = Utilities.helpers.bytesToString(payload);
        try {
            ArrayList<String> keys = new ArrayList<>(Arrays.asList(unparsed.split(":")));

            boolean isArray = Utilities.parseArrayIndex(keys.get(0)) != -1;
            Object base;
            if (isArray) {
                if (root.isJsonArray()) {
                    base = new ObjectMapper().readValue(baseInput, ArrayList.class);
                }
                else {
                    base = new ArrayList();
                }
            }
            else {
                if(root.isJsonObject()) {
                    base = new ObjectMapper().readValue(baseInput, HashMap.class);
                }
                else {
                    base = new HashMap();
                }
            }

            Object next = base;
            for (int i = 0; i < keys.size(); i++) {

                String key = keys.get(i);
                boolean setValue = i+1 == keys.size();

                int index = Utilities.parseArrayIndex(key);
                if (index != -1) {
                    ArrayList injectionPoint = (ArrayList) next;
                    if (injectionPoint.size() < index+1) {
                        for(int k=injectionPoint.size(); k<index; k++) {
                            injectionPoint.add(Utilities.generateCanary());
                        }
                        injectionPoint.add(makeNode(keys, i, unparsed));
                    }
                    else if (injectionPoint.get(index) == null || setValue) {
                        injectionPoint.set(index, makeNode(keys, i, unparsed));
                    }
                    next = injectionPoint.get(index);
                } else {
                    HashMap injectionPoint = (HashMap) next;
                    if (!injectionPoint.containsKey(key) || setValue) {
                        injectionPoint.put(key, makeNode(keys, i, unparsed));
                    }
                    next = injectionPoint.get(key);
                }
            }

            String mergedJson = new ObjectMapper().writeValueAsString(base);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(headers);
            outputStream.write(Utilities.helpers.stringToBytes(mergedJson));
            return Utilities.fixContentLength(outputStream.toByteArray());

        }
        catch (Exception e) {
            Utilities.out("Error with "+unparsed);
            e.printStackTrace(new PrintStream(Utilities.callbacks.getStdout()));
            return buildRequest(Utilities.helpers.stringToBytes("error_"+unparsed.replace(":", "_")));
            // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
        }
    }
}






