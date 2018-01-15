package burp;

import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;


import java.util.ArrayList;
import java.util.List;


class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static final boolean THOROUGH_MODE = true;
    static final boolean DEBUG = false;
    static final boolean TRANSFORMATION_SCAN = true;
    static final boolean DIFFING_SCAN = true;
    static final byte CONFIRMATIONS = 5;

    static final boolean BRUTEFORCE = true;
    static final boolean DYNAMIC_KEYLOAD = false;
    static final boolean MAX_ONE_PER_HOST = true;
    static final int THREAD_POOL_SIZE = 32;
    static final int ROTATION_INTERVAL = 6;


    static AtomicBoolean unloaded = new AtomicBoolean(false);

    static final boolean TRY_HPP = true;
    static final boolean TRY_HPP_FOLLOWUP = false;
    static final boolean TRY_SYNTAX_ATTACKS = true;
    static final boolean TRY_VALUE_PRESERVING_ATTACKS = true;
    static final boolean TRY_EXPERIMENTAL_CONCAT_ATTACKS = true;
    static final boolean TRY_MAGIC_VALUE_ATTACKS = true;
    static final byte PARAM_HEADER = 7;

    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    static HashSet<String> phpFunctions = new HashSet<>();
    static ArrayList<String> paramNames = new ArrayList<>();
    static HashSet<String> headerNames = new HashSet<>();

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

        Scanner params = new Scanner(getClass().getResourceAsStream("/params"));
        while (params.hasNext()) {
            paramNames.add(params.next());
        }
        params.close();

        Scanner headers = new Scanner(getClass().getResourceAsStream("/boring_headers"));
        while (headers.hasNext()) {
            headerNames.add(headers.next().toLowerCase());
        }
    }

    static String getNameFromType(byte type) {
        switch (type) {
            case IParameter.PARAM_BODY:
                return "body";
            case IParameter.PARAM_URL:
                return "url";
            case IParameter.PARAM_COOKIE:
                return "cookie";
            case IParameter.PARAM_JSON:
                return "json";
            case Utilities.PARAM_HEADER:
                return "header";
            default:
                return "unknown";
        }
    }

    static int generate(int seed, int count, List<String> accumulator)
    {

        int num = seed;
        int limit = seed + count;
        for (; num < limit; num++) {
            String word = num2word(num);
            if(word != null)
            {
                accumulator.add(word);
            }
            else
            {
                limit++;
            }
        }
        return num;
    }

    private static String num2word(int num)
    {
        String number = num2String(num);
        if (number.contains("0"))
        {
            return null;
        }
        return number;
    }

    private static char[] DIGITS = {'0', 'a' , 'b' ,
            'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
            'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
            'o' , 'p' , 'q' , 'r' , 's' , 't' ,
            'u' , 'v' , 'w' , 'x' , 'y' , 'z'};

    private static String num2String(int i) {

        if(i < 0)
        {
            throw new IllegalArgumentException("+ve integers only please");
        }

        char buf[] = new char[7];
        int charPos = 6;

        i = -i;

        while (i <= -DIGITS.length) {
            buf[charPos--] = DIGITS[-(i % DIGITS.length)];
            i = i / DIGITS.length;
        }
        buf[charPos] = DIGITS[-i];

        return new String(buf, charPos, (7 - charPos));
    }



    static boolean invertable(String value) {
        return !value.equals(invert(value));
    }

    static Object invert(String value) {
        if (value != null) {
            if (value.equals("true")) {
                return false;
            } else if (value.equals("false")) {
                return true;
            }
            else if (value.equals("1")) {
                return 0;
            }
            else if (value.equals("0")) {
                return 1;
            }
        }
        return value;
    }

    static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(START_CHARSET.charAt(rnd.nextInt(START_CHARSET.length())));
        for (int i = 1; i < len; i++)
            sb.append(CHARSET.charAt(rnd.nextInt(CHARSET.length())));
        return sb.toString();
    }

    static String mangle(String seed) {
        Random seededRandom = new Random(seed.hashCode());
        StringBuilder sb = new StringBuilder(7);
        sb.append(START_CHARSET.charAt(seededRandom.nextInt(START_CHARSET.length())));
        for (int i = 1; i < 8; i++)
            sb.append(CHARSET.charAt(seededRandom.nextInt(CHARSET.length())));
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

    static String getBody(byte[] response) {
        if (response == null) { return ""; }
        int bodyStart = Utilities.getBodyStart(response);
        String body = Utilities.helpers.bytesToString(Arrays.copyOfRange(response, bodyStart, response.length));
        return body;
    }

    static String generateCanary() {
        return randomString(4+rnd.nextInt(7)) + Integer.toString(rnd.nextInt(9));
    }

    private static String sensibleURL(URL url) {
        String out = url.toString();
        if (url.getDefaultPort() == url.getPort()) {
            out = out.replaceFirst(":" + Integer.toString(url.getPort()), "");
        }
        return out;
    }

    public static URL getURL(IHttpRequestResponse request) {
        IHttpService service = request.getHttpService();
        URL url;
        try {
            url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request.getRequest()));
        } catch (java.net.MalformedURLException e) {
            url = null;
        }
        return url;
    }

    static int parseArrayIndex(String key) {
        try {
            if (key.length() > 2 && key.startsWith("[") && key.endsWith("]")) {
                return Integer.parseInt(key.substring(1, key.length() - 1));
            }
        }
        catch (NumberFormatException e) {

        }
        return -1;
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
        // Utilities.out("#"+response.length);
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    static byte[] replace(byte[] request, byte[] find, byte[] replace) {
        List<int[]> matches = getMatches(request, find, -1);
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (int i=0;i<matches.size();i++) {
                if (i == 0) {
                    outputStream.write(Arrays.copyOfRange(request, 0, matches.get(i)[0]));
                }
                else {
                    outputStream.write(Arrays.copyOfRange(request, matches.get(i-1)[1], matches.get(i)[0]));
                }
                outputStream.write(replace);

                if (i==matches.size()-1) {
                    outputStream.write(Arrays.copyOfRange(request, matches.get(i)[1], request.length));
                    break;
                }
            }
            request = outputStream.toByteArray();
        } catch (IOException e) {
            return null;
        }

        return request;
    }

    static byte[] appendToPath(byte[] request, String suffix) {
        if (suffix == null || suffix.equals("")) {
            return request;
        }

        int i = 0;
        while (i < request.length && request[i++] != '\n') {
        }

        int j = 0;
        while (j < i && request[j++] != '?') {
        }

        if(j >= i) {
            request = replace(request, " HTTP/1.1".getBytes(), (suffix+" HTTP/1.1").getBytes());
        }
        else {
            request = replace(request, "?".getBytes(), (suffix+"?").getBytes()); // fixme replace can't handle single-char inputs
        }

        return request;
    }

    static List<int[]> getMatches(byte[] response, byte[] match, int giveUpAfter) {
        if (giveUpAfter == -1) {
            giveUpAfter = response.length;
        }

        List<int[]> matches = new ArrayList<>();

//        if (match.length < 4) {
//            return matches;
//        }

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

    public static void doActiveScan(IHttpRequestResponse req, int[] offsets) {
        String host = helpers.analyzeRequest(req).getUrl().getHost();
        int port = helpers.analyzeRequest(req).getUrl().getPort();
        boolean useHTTPS = helpers.analyzeRequest(req).getUrl().toString().startsWith("https");
        ArrayList<int[]> offsetList = new ArrayList<>();
        offsetList.add(offsets);
        try {
            callbacks.doActiveScan(
                    host, port, useHTTPS, req.getRequest(), offsetList
            );
        } catch (IllegalArgumentException e) {
            Utilities.err("Couldn't scan, bad insertion points: "+Arrays.toString(offsetList.get(0)));
        }
    }

    static String toCanary(String payload) {
        return "wrtqva" + mangle(payload);
    }

    public static int getBodyStart(byte[] response) {
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

    public static String getHeader(byte[] request, String header) {
        int[] offsets = getHeaderOffsets(request, header);
        String value = helpers.bytesToString(Arrays.copyOfRange(request, offsets[1], offsets[2]));
        return value;
    }

    public static boolean containsBytes(byte[] request, byte[] value) {
        return helpers.indexOf(request, value, false, 1, request.length - 1) != -1;
    }

    public static byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write( Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(helpers.stringToBytes(value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            Utilities.out("header locating fail");
            throw new RuntimeException("Can't find the header");
        }
    }

    public static String encodeJSON(String input) {
        input = input.replace("\\", "\\\\");
        input = input.replace("\"", "\\\"");
        return input;
    }

    public static int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    // todo refactor to use getHeaderOffsets
    // fixme fails if the modified header is the last header
    public static byte[] addOrReplaceHeader(byte[] request, String header, String value) {
        try {
            int i = 0;
            int end = request.length;
            while (i < end && request[i++] != '\n') {
            }
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            while (i < end) {
                int line_start = i;
                while (i < end && request[i++] != ' ') {
                }
                byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
                int headerValueStart = i;
                while (i < end && request[i++] != '\n') {
                }
                if (i == end) {
                    break;
                }

                if(i+2<end && request[i] == '\r' && request[i+1] == '\n') {
                    outputStream.write(Arrays.copyOfRange(request, 0, i));
                    outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n"));
                    outputStream.write(Arrays.copyOfRange(request, i, end));
                    return outputStream.toByteArray();
                }

                String header_str = helpers.bytesToString(header_name);

                if (header.equals(header_str)) {

                    outputStream.write(Arrays.copyOfRange(request, 0, headerValueStart));
                    outputStream.write(helpers.stringToBytes(value));
                    outputStream.write(Arrays.copyOfRange(request, i-2, end));
                    return outputStream.toByteArray();
                }
            }
            outputStream.write(Arrays.copyOfRange(request, 0, end-2));
            outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n\r\n"));
            return outputStream.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        }
    }

    static boolean isResponse(byte[] data) {
        byte[] start = Arrays.copyOfRange(data, 0, 4);
        return (helpers.bytesToString(start).equals("HTTP/"));
    }

    public static byte[] fixContentLength(byte[] request) {
        if (countMatches(request, helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = Utilities.getBodyStart(request);
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        }
        else {
            return request;
        }
    }

//    static byte[] addBulkParams(byte[] request, String name, String value, byte type) {
//
//    }

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

    static IHttpRequestResponse attemptRequest(IHttpService service, byte[] req) {
        if(unloaded.get()) {
            Utilities.out("Extension unloaded - aborting attack");
            throw new RuntimeException("Extension unloaded");
        }

        IHttpRequestResponse result = null;

        for(int attempt=1; attempt<3; attempt++) {
            try {
                result = callbacks.makeHttpRequest(service, req);
            } catch(RuntimeException e) {
                Utilities.log(e.toString());
                Utilities.log("Critical request error, retrying...");
                continue;
            }

            if (result.getResponse() == null) {
                Utilities.log("Request failed, retrying...");
                //requestResponse.setResponse(new byte[0]);
            }
            else {
                break;
            }
        }

        if (result.getResponse() == null) {
            Utilities.log("Request failed multiple times, giving up");
        }

        return result;
    }

    static Attack buildTransformationAttack(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String leftAnchor, String payload, String rightAnchor) {

        IHttpRequestResponse req = attemptRequest(baseRequestResponse.getHttpService(),
                insertionPoint.buildRequest(helpers.stringToBytes(insertionPoint.getBaseValue() + leftAnchor + payload + rightAnchor)));

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
        return payload.replace("%", "%25").replace("\u0000", "%00").replace("&", "%26").replace("#", "%23").replace("\u0020", "%20").replace(";", "%3b").replace("+", "%2b").replace("\n", "%0A").replace("\r", "%0d");
    }


    static boolean identical(Attack candidate, Attack attack2) {
        return candidate.getPrint().equals(attack2.getPrint());
    }

    static boolean similarIsh(Attack noBreakGroup, Attack breakGroup, Attack noBreak, Attack doBreak) {

        for (String key: noBreakGroup.getPrint().keySet()) {
            Object noBreakVal = noBreakGroup.getPrint().get(key);

            if(key.equals("input_reflections") && noBreakVal.equals(Attack.INCALCULABLE)) {
                continue;
            }

            // if this attribute is inconsistent, make sure it's different this time
            if (!breakGroup.getPrint().containsKey(key)) {
                if (!noBreakVal.equals(doBreak.getPrint().get(key))) {
                    return false;
                }
            }
            else if (!noBreakVal.equals(breakGroup.getPrint().get(key))) {
                // if it's consistent and different, these responses definitely don't match
                return false;
            }
        }

        for (String key: breakGroup.getPrint().keySet()) {
            if (!noBreakGroup.getPrint().containsKey(key)) {
                // if this attribute is inconsistent, make sure it's different this time
                if (!breakGroup.getPrint().get(key).equals(noBreak.getPrint().get(key))){
                    return false;
                }
            }
        }

        return true;
    }

    static boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
        //if (!candidate.getPrint().keySet().equals(individualBreakAttack.getPrint().keySet())) {
        //    return false;
        //}

        for (String key: doNotBreakAttackGroup.getPrint().keySet()) {
            if (!individualBreakAttack.getPrint().containsKey(key)){
                return false;
            }
            if (individualBreakAttack.getPrint().containsKey(key) && !individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    static boolean verySimilar(Attack attack1, Attack attack2) {
        if (!attack1.getPrint().keySet().equals(attack2.getPrint().keySet())) {
            return false;
        }

        for (String key: attack1.getPrint().keySet()) {
            if(key.equals("input_reflections") && (attack1.getPrint().get(key).equals(Attack.INCALCULABLE) || attack2.getPrint().get(key).equals(Attack.INCALCULABLE))) {
                continue;
            }

            if (attack2.getPrint().containsKey(key) && !attack2.getPrint().get(key).equals(attack1.getPrint().get(key))) {
                return false;
            }
        }

        return true;
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse) {
        return reportReflectionIssue(attacks, baseRequestResponse, "");
    }

    static IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse, String title) {
        IHttpRequestResponse[] requests = new IHttpRequestResponse[attacks.length];
        Probe bestProbe = null;
        boolean reliable = false;
        String detail = "<br/><br/><b>Successful probes</b><br/>";
        String reportedSeverity = "High";
        int evidenceCount = 0;

        for (int i=0; i<attacks.length; i++) {
            requests[i] = attacks[i].getLastRequest(); // was getFirstRequest
            if (i % 2 == 0) {
                detail += " &#160;  &#160; <table><tr><td><b>"+StringEscapeUtils.escapeHtml4(attacks[i].getProbe().getName())+" &#160;  &#160; </b></td><td><b>"+ StringEscapeUtils.escapeHtml4(attacks[i].payload)+ " &#160; </b></td><td><b>";
            }
            else {
                detail += StringEscapeUtils.escapeHtml4(attacks[i].payload)+"</b></td></tr>\n";
                HashMap<String, Object> workedPrint = attacks[i].getLastPrint(); // was getFirstPrint
                HashMap<String, Object> consistentWorkedPrint = attacks[i].getPrint();
                HashMap<String, Object> breakPrint = attacks[i-1].getLastPrint(); // was getFirstPrint
                HashMap<String, Object> consistentBreakPrint = attacks[i-1].getPrint();

                Set<String> allKeys = new HashSet<>(consistentWorkedPrint.keySet());
                allKeys.addAll(consistentBreakPrint.keySet());
                String boringDetail = "";

                for (String mark: allKeys) {
                    String brokeResult = breakPrint.get(mark).toString();
                    String workedResult = workedPrint.get(mark).toString();

                    if(brokeResult.equals(workedResult)) {
                        continue;
                    }

                    evidenceCount++;

                    try {
                        if (Math.abs(Integer.parseInt(brokeResult)) > 9999) {
                            brokeResult = "X";
                        }
                        if (Math.abs(Integer.parseInt(workedResult)) > 9999) {
                            workedResult = "Y";
                        }
                    }
                    catch (NumberFormatException e) {
                        brokeResult = StringEscapeUtils.escapeHtml4(brokeResult);
                        workedResult = StringEscapeUtils.escapeHtml4(workedResult);
                    }

                    if (consistentBreakPrint.containsKey(mark) && consistentWorkedPrint.containsKey(mark)) {
                        detail += "<tr><td>" + StringEscapeUtils.escapeHtml4(mark) + "</td><td>" + "" + brokeResult + " </td><td>" + workedResult + "</td></tr>\n";
                        reliable = true;
                    }
                    else if (consistentBreakPrint.containsKey(mark)) {
                        boringDetail += "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark)+"</i></td><td><i>" + brokeResult + "</i></td><td><i> *" + workedResult + "*</i></td></tr>\n";
                    }
                    else {
                        boringDetail += "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark)+"</i></td><td><i>*" + brokeResult + "*</i></td><td><i>" + workedResult + "</i></td></tr>\n";
                    }

                }
                detail += boringDetail;
                detail += "</table>\n";

                String tip = attacks[i].getProbe().getTip();
                if (!"".equals(tip)) {
                    detail += "&nbsp;<i>"+tip+"</i>";
                }
            }

            if (bestProbe == null || attacks[i].getProbe().getSeverity() >= bestProbe.getSeverity()) {
                bestProbe = attacks[i].getProbe();

                int severity = bestProbe.getSeverity();
                if (severity < 3) {
                    reportedSeverity = "Low";
                }
                else if (severity < 7) {
                    reportedSeverity = "Medium";
                }

            }
        }

        if (evidenceCount == 1) {
            reportedSeverity = "Information";
        }

        if ("".equals(title)) {
            title = "Interesting input handling:" +bestProbe.getName();
        }

        return new Fuzzable(requests, helpers.analyzeRequest(baseRequestResponse).getUrl(), title, detail, reliable, reportedSeverity); //attacks[attacks.length-2].getProbe().getName()
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


