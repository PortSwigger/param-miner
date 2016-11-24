package burp;

import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Backslash Powered Scanner";
    private static final String version = "0.863";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
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

        callbacks.registerScannerCheck(new FastScan(callbacks));

        Utilities.out("Loaded " + name + " v" + version);
        Utilities.out("Debug mode: " + Utilities.DEBUG);
        Utilities.out("Thorough mode: " + Utilities.THOROUGH_MODE);
    }
}

class FastScan implements IScannerCheck {
    private TransformationScan transformationScan;
    private DiffingScan diffingScan;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    public FastScan(final IBurpExtenderCallbacks callbacks) {
        transformationScan = new TransformationScan(callbacks);
        diffingScan = new DiffingScan();
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
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

        IParameter baseParam = getParameterFromInsertionPoint(insertionPoint, baseRequestResponse.getRequest());
        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL)) {
            insertionPoint = new ParamInsertionPoint(baseRequestResponse.getRequest(), baseParam.getName(), baseParam.getValue(), baseParam.getType());
        }

        ArrayList<IScanIssue> issues = new ArrayList<>();
        String leftAnchor = Utilities.randomString(5);
        String rightAnchor = "z" + Utilities.randomString(2);
        Attack basicAttack = Utilities.buildTransformationAttack(baseRequestResponse, insertionPoint, leftAnchor, "\\\\", rightAnchor);

        issues.add(diffingScan.findReflectionIssues(baseRequestResponse, insertionPoint, basicAttack));

        if (!Utilities.getMatches(Utilities.filterResponse(basicAttack.req.getResponse()), (leftAnchor + "\\" + rightAnchor).getBytes(), -1).isEmpty()) {
            issues.add(transformationScan.findTransformationIssues(baseRequestResponse, insertionPoint, basicAttack.req));
        }

        issues.removeAll(Collections.singleton(null));
        if (baseParam != null && (baseParam.getType() == IParameter.PARAM_BODY || baseParam.getType() == IParameter.PARAM_URL) && Utilities.getExtension(baseRequestResponse.getRequest()).equals(".php")) {

            String param_name = baseParam.getName() + "[]";

            byte[] newReq = helpers.removeParameter(baseRequestResponse.getRequest(), baseParam);
            IParameter newParam = helpers.buildParameter(param_name, baseParam.getValue(), baseParam.getType());
            newReq = helpers.addParameter(newReq, helpers.buildParameter(param_name, "", baseParam.getType()));
            newReq = helpers.addParameter(newReq, newParam);

            IScannerInsertionPoint arrayInsertionPoint = new ParamInsertionPoint(newReq, param_name, newParam.getValue(), newParam.getType());
            IHttpRequestResponse newBase = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), arrayInsertionPoint.buildRequest(newParam.getValue().getBytes()));
            basicAttack = Utilities.buildTransformationAttack(newBase, arrayInsertionPoint, leftAnchor, "\\\\", rightAnchor);
            issues.add(diffingScan.findReflectionIssues(newBase, arrayInsertionPoint, basicAttack));
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
    private final static String DETAIL = "The application reacts to inputs in a way that suggests it might be vulnerable to some kind of server-side code injection. The probes are listed below in chronological order.";
    private final static String REMEDIATION = "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of of manual investigation. Try to determine the root cause of the observed behaviour." +
            "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results. ";
    private final static String SEVERITY = "High";
    private final static String CONFIDENCE = "Firm";

    public Fuzzable(IHttpRequestResponse[] requests, URL url, String title, String detail) {
        super(requests[0].getHttpService(), url, requests, NAME + title, DETAIL + detail, SEVERITY, CONFIDENCE, REMEDIATION);
    }

}

class InputTransformation extends CustomScanIssue {
    private final static String NAME = "Suspicious input transformation";
    private final static String DETAIL = "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection";
    private final static String REMEDIATION =
            "This issue does not necessarily indicate a vulnerability; it is merely highlighting behaviour worthy of manual investigation. " +
                    "Try to determine the root cause of the observed input transformations." +
                    "Refer to <a href='http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html'>Backslash Powered Scanning</a> for further details and guidance interpreting results.";
    private final static String CONFIDENCE = "Tentative";

    public InputTransformation(ArrayList<String> interesting, ArrayList<String> boring, IHttpRequestResponse base, URL url, String paramName) {
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
        String details = DETAIL + "<br/><br/>Affected parameter:<code>" + paramName + "</code><br/><br/>";
        details += "<p>Interesting transformations:</p><ul> ";
        for (String transform : interesting) {
            details += "<li><b><code style='font-size: 125%;'>" + transform + "</code></b></li>";
        }
        details += "</ul><p>Boring transformations:</p><ul>";
        for (String transform : boring) {
            details += "<li><b><code>" + transform + "</code></b></li>";
        }
        details += "</ul>";
        return details;
    }
}

class ParamInsertionPoint implements IScannerInsertionPoint {
    private byte[] request;
    private String name;
    private String value;
    private byte type;

    public ParamInsertionPoint(byte[] request, String name, String value, byte type) {
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
        return IScannerInsertionPoint.INS_PARAM_BODY;
        // return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
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

    public CustomScanIssue(
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

    @Override
    public String getHost() {
        return null;
    }

    @Override
    public int getPort() {
        return 0;
    }

    @Override
    public String getProtocol() {
        return null;
    }

}
