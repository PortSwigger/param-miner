package burp;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static final boolean THOROUGH_MODE = true;
    static final boolean DEBUG = false;
    static final boolean TRANSFORMATION_SCAN = false;
    static final byte CONFIRMATIONS = 6;

    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    private static HashSet<String> phpFunctions = new HashSet<>();

    private static final String CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"; // ABCDEFGHIJKLMNOPQRSTUVWXYZ
    private static final String START_CHARSET = "ghijklmnopqrstuvwxyz";
    static Random rnd = new Random();

    Utilities(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();

        Scanner s = new Scanner(getClass().getResourceAsStream("/functions"));
        while (s.hasNext()) {
            phpFunctions.add(s.next());
        }
        s.close();

    }

    static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(START_CHARSET.charAt(rnd.nextInt(START_CHARSET.length())));
        for (int i = 1; i < len; i++)
            sb.append(CHARSET.charAt(rnd.nextInt(CHARSET.length())));
        return sb.toString();
    }

    static void out(String message) {
        stdout.println(message);
    }
    static void err(String message) {
        stderr.println(message);
    }

    static void log(String message) {
        if (DEBUG) {
            stdout.println(message);
        }
    }

    private static String sensibleURL(URL url) {
        String out = url.toString();
        if (url.getDefaultPort() == url.getPort()) {
            out = out.replaceFirst(":" + Integer.toString(url.getPort()), "");
        }
        return out;
    }

    private static URL getURL(IHttpRequestResponse request) {
        IHttpService service = request.getHttpService();
        URL url;
        try {
            url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request.getRequest()));
        } catch (java.net.MalformedURLException e) {
            url = null;
        }
        return url;
    }


    static boolean mightBeOrderBy(String name, String value) {
        return (name.toLowerCase().contains("order") ||
                name.toLowerCase().contains("sort")) ||
                value.toLowerCase().equals("asc") ||
                value.toLowerCase().equals("desc") ||
                (StringUtils.isNumeric(value) && Double.parseDouble(value) <= 1000) ||
                (value.length() < 20 && StringUtils.isAlpha(value));
    }

    static boolean mightBeIdentifier(String value) {
        for (int i=0; i<value.length(); i++) {
            char x = value.charAt(i);
            if (!(CharUtils.isAsciiAlphanumeric(x) || x == '.' || x == '-' || x == '_' || x == ':' || x == '$') ) {
                return false;
            }
        }
        return true;
    }

    static boolean mightBeFunction(String value) {
        return phpFunctions.contains(value);
    }

    // records from the first space to the second space
    private static String getPathFromRequest(byte[] request) {
        int i = 0;
        boolean recording = false;
        String path = "";
        while (i < request.length) {
            byte x = request[i];

            if (recording) {
                if (x != ' ') {
                    path += (char) x;
                } else {
                    break;
                }
            } else {
                if (x == ' ') {
                    recording = true;
                }
            }
            i++;
        }
        return path;
    }

    static String getExtension(byte[] request) {
        String url = getPathFromRequest(request);
        int query_start = url.indexOf('?');
        if (query_start == -1) {
            query_start = url.length();
        }
        url = url.substring(0, query_start);
        int last_dot = url.lastIndexOf('.');
        if (last_dot == -1) {
            return "";
        }
        else {
            return url.substring(last_dot);
        }
    }



    static IHttpRequestResponse fetchFromSitemap(URL url) {
        IHttpRequestResponse[] pages = callbacks.getSiteMap(sensibleURL(url));
        for (IHttpRequestResponse page : pages) {
            if (page.getResponse() != null) {
                if (url.equals(getURL(page))) {
                    return page;
                }
            }
        }
        return null;
    }

    static int countByte(byte[] response, byte match) {
        int count = 0;
        int i = 0;
        while (i < response.length) {
            if (response[i] == match) {
                count +=1 ;
            }
            i += 1;
        }
        return count;
    }

    static int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    static List<int[]> getMatches(byte[] response, byte[] match, int giveUpAfter) {
        if (giveUpAfter == -1) {
            giveUpAfter = response.length;
        }

        List<int[]> matches = new ArrayList<>();

        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < giveUpAfter) {
            start = helpers.indexOf(response, match, true, start, giveUpAfter);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    private static int getBodyStart(byte[] response) {
        int i = 0;
        int newlines_seen = 0;
        while (i < response.length) {
            byte x = response[i];
            if (x == '\n') {
                newlines_seen++;
            } else if (x != '\r') {
                newlines_seen = 0;
            }

            if (newlines_seen == 2) {
                break;
            }
            i += 1;
        }


        while (i < response.length && (response[i] == ' ' || response[i] == '\n' || response[i] == '\r')) {
            i++;
        }

        return i;
    }

    static String getStartType(byte[] response) {
        int i = getBodyStart(response);

        String start = "";
        if (i == response.length) {
            start = "[blank]";
        }
        else if (response[i] == '<') {
            while (i < response.length && (response[i] != ' ' && response[i] != '\n' && response[i] != '\r' && response[i] != '>')) {
                start += (char) (response[i] & 0xFF);
                i += 1;
            }
        }
        else {
            start = "text";
        }

        return start;
    }

    static List<IParameter> getExtraInsertionPoints(byte[] request) { //
        List<IParameter> params = new ArrayList<>();
        int end = getBodyStart(request);
        int i = 0;
        while(i < end && request[i++] != ' ') {} // walk to the url start
        while(i < end) {
            byte c = request[i];
            if (c == ' ' ||
                    c == '?' ||
                    c == '#') {
                break;
            }
            i++;
        }

        params.add(new PartialParam("path", i, i));
        while(request[i++] != '\n' && i < end) {}

        String[] to_poison = {"User-Agent", "Referer", "X-Forwarded-For", "Host"};
        while(i<end) {
            int line_start = i;
            while(i < end && request[i++] != ' ') {}
            byte[] header_name = Arrays.copyOfRange(request, line_start, i-2);
            int headerValueStart = i;
            while(i < end && request[i++] != '\n') {}
            if (i == end) { break; }

            String header_str = helpers.bytesToString(header_name);
            for (String header: to_poison) {
                if (header.equals(header_str)) {
                    params.add(new PartialParam(header, headerValueStart, i-2));
                }
            }
        }


        return params;
    }

    static boolean isHTTP(URL url) {
        String protocol = url.getProtocol().toLowerCase();
        return "https".equals(protocol);
    }

    static IHttpRequestResponse highlightRequestResponse(IHttpRequestResponse attack, String responseHighlight, String requestHighlight, IScannerInsertionPoint insertionPoint) {
        List<int[]> requestMarkers = new ArrayList<>(1);
        if (requestHighlight != null && requestHighlight.length() > 2) {
            requestMarkers.add(insertionPoint.getPayloadOffsets(requestHighlight.getBytes()));
        }

        List<int[]> responseMarkers = new ArrayList<>(1);
        if (responseHighlight != null) {
            responseMarkers = getMatches(attack.getResponse(), responseHighlight.getBytes(), -1);
        }

        attack = callbacks.applyMarkers(attack, requestMarkers, responseMarkers);
        return attack;
    }

    static Attack buildTransformationAttack(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String leftAnchor, String payload, String rightAnchor) {

        IHttpRequestResponse req = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), insertionPoint.buildRequest(helpers.stringToBytes(insertionPoint.getBaseValue() + leftAnchor + payload +rightAnchor)));

        return new Attack(Utilities.highlightRequestResponse(req, leftAnchor, leftAnchor+payload+rightAnchor, insertionPoint), null, payload, "");
    }

    static byte[] filterResponse(byte[] response) {

        if (response == null) {
            return new byte[]{'n','u','l','l'};
        }
        byte[] filteredResponse;
        IResponseInfo details = helpers.analyzeResponse(response);

        String inferredMimeType = details.getInferredMimeType();
        if(inferredMimeType.isEmpty()) {
            inferredMimeType = details.getStatedMimeType();
        }
        inferredMimeType = inferredMimeType.toLowerCase();

        if(inferredMimeType.contains("text") || inferredMimeType.equals("html") || inferredMimeType.contains("xml") || inferredMimeType.contains("script") || inferredMimeType.contains("css") || inferredMimeType.contains("json")) {
            filteredResponse = helpers.stringToBytes(helpers.bytesToString(response).toLowerCase());
        }
        else {
            String headers = helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset())) + details.getInferredMimeType();
            filteredResponse = helpers.stringToBytes(headers.toLowerCase());
        }

        if(details.getStatedMimeType().toLowerCase().contains("json") && (inferredMimeType.contains("json") || inferredMimeType.contains("javascript"))) {
            String headers = helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset()));
            String body =  helpers.bytesToString(Arrays.copyOfRange(response, details.getBodyOffset(), response.length));
            filteredResponse = helpers.stringToBytes(headers + StringEscapeUtils.unescapeJson(body));
        }

        return filteredResponse;
    }

    static String encodeParam(String payload) {
        return payload.replace("%", "%25").replace("\u0000", "%00").replace("&", "%26").replace("#", "%23").replace("\u0020", "%20").replace(";", "%3b").replace("+", "%2b");
    }


    static boolean identical(Attack candidate, Attack attack2) {
        return candidate.getPrint().equals(attack2.getPrint());
    }

    static boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
        //if (!candidate.getPrint().keySet().equals(individualBreakAttack.getPrint().keySet())) {
        //    return false;
        //}
        for (String key: doNotBreakAttackGroup.getPrint().keySet()) {
            if (individualBreakAttack.getPrint().containsKey(key) && !individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse) {
        IHttpRequestResponse[] requests = new IHttpRequestResponse[attacks.length];
        Probe bestProbe = null;
        boolean reliable = false;
        String detail = "<br/><br/><b>Successful probes</b><br/><ul style='list-style-type: none'>";
        for (int i=0; i<attacks.length; i++) {
            requests[i] = attacks[i].getFirstRequest();
            if (i % 2 == 0) {
                detail += "<li><b>"+StringEscapeUtils.escapeHtml4(attacks[i].getProbe().getName())+"</b> &#x20; (<b style='color: red'>"+ StringEscapeUtils.escapeHtml4(attacks[i].payload)+ "</b> vs <b style='color: blue'> ";
            }
            else {
                detail += StringEscapeUtils.escapeHtml4(attacks[i].payload)+"</b>)</li>";
                detail += "<ul style='list-style-type: circle'>";
                HashMap<String, Object> workedPrint = attacks[i].getPrint();
                HashMap<String, Object> breakPrint = attacks[i-1].getFirstPrint();
                HashMap<String, Object> consistentBreakPrint = attacks[i-1].getPrint();
                for (String mark : workedPrint.keySet()) {
                    if (consistentBreakPrint.containsKey(mark) && !workedPrint.get(mark).equals(consistentBreakPrint.get(mark))) {
                        detail += "<li>" + StringEscapeUtils.escapeHtml4(mark)+": "+"<b style='color: red'>"+StringEscapeUtils.escapeHtml4(breakPrint.get(mark).toString()) + " </b>vs<b style='color: blue'> "+StringEscapeUtils.escapeHtml4(workedPrint.get(mark).toString()) + "</b></li>";
                        reliable = true;
                    }
                    else if (breakPrint.containsKey(mark) && !workedPrint.get(mark).equals(breakPrint.get(mark))) {
                        detail += "<li><span style='color: #6688ff'>" + StringEscapeUtils.escapeHtml4(mark)+"</span>: "+"<b style='color: red'>"+StringEscapeUtils.escapeHtml4(breakPrint.get(mark).toString()) + " </b>vs<b style='color: blue'> "+StringEscapeUtils.escapeHtml4(workedPrint.get(mark).toString()) + "</b></li>";
                    }
                }

                detail += "</ul>";
            }
            if (bestProbe == null || attacks[i].getProbe().getSeverity() >= bestProbe.getSeverity()) {
                bestProbe = attacks[i].getProbe();
            }
        }

        detail += "</ul>";

        return new Fuzzable(requests, helpers.analyzeRequest(baseRequestResponse).getUrl(), bestProbe.getName(), detail, reliable); //attacks[attacks.length-2].getProbe().getName()
    }
}

class PartialParam implements IParameter {

    private int valueStart, valueEnd;
    private String name;

    PartialParam(String name, int valueStart, int valueEnd) {
        this.name = name;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
    }

    @Override
    public byte getType() {
        return IParameter.PARAM_COOKIE;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return null;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return 0;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
}


