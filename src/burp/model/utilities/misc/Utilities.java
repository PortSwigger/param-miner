package burp.model.utilities.misc;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.model.scanning.guessing.param.PartialParam;
import burp.model.utilities.burp.Fuzzable;
import burp.model.utilities.burp.LazyRequestInfo;
import burp.model.utilities.scan.Attack;
import burp.model.utilities.scan.Probe;
import burp.view.ConfigurableSettings;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

///////////////////////////////////////
// CLASS Utilities
///////////////////////////////////////
public class Utilities {

/////////////////////////////
// PUBLIC FIELDS
/////////////////////////////
public static final byte                   PARAM_HEADER        = 7;
public static final HashSet<String>        phpFunctions        = new HashSet<>();
public static final ArrayList<String>      paramNames          = new ArrayList<>();
public static final HashSet<String>        boringHeaders       = new HashSet<>();
public static final Set<String>            reportedParams      = ConcurrentHashMap.newKeySet();

public static boolean                chopNestedResponses = false;
public final  AtomicInteger          requestCount        = new AtomicInteger(0);
public final  IBurpExtenderCallbacks callbacks;
public final  IExtensionHelpers      helpers;
public final  AtomicBoolean          unloaded            = new AtomicBoolean(false);
public final  String                 name;

public ConfigurableSettings globalSettings;
public boolean              supportsHTTP2 = true;

/////////////////////////////
// PUBLIC FUNCTIONS
/////////////////////////////
//-----------------------------------------------------------------------------
public Utilities(IBurpExtenderCallbacks incallbacks, HashMap<String, Object> settings, String name) {
  this.name = name;
  callbacks = incallbacks;
  stdout    = new PrintWriter(callbacks.getStdout(), true);
  stderr    = new PrintWriter(callbacks.getStderr(), true);
  helpers   = callbacks.getHelpers();
  out("This extension should be run on the latest version of Burp Suite. Using an older version of Burp may cause " +
    "impaired functionality.");
  if(settings != null) {
    globalSettings = new ConfigurableSettings(settings, this.callbacks);
  }
  
}

//-----------------------------------------------------------------------------
public static String getHeaders(byte[] response) {
  if(response == null) {
    return "";
  }
  else {
    int    bodyStart = getBodyStart(response);
    String body      = new String(Arrays.copyOfRange(response, 0, bodyStart));
    body = body.substring(body.indexOf("\n") + 1);
    return body;
  }
}

//-----------------------------------------------------------------------------
public static int getBodyStart(byte[] response) {
  int i = 0;
  
  for(int newlines_seen = 0; i < response.length; ++i) {
    byte x = response[i];
    if(x == 10) {
      ++newlines_seen;
    }
    else if(x != 13) {
      newlines_seen = 0;
    }
    
    if(newlines_seen == 2) {
      ++i;
      break;
    }
  }
  
  return i;
}

//-----------------------------------------------------------------------------
public static String getMethod(byte[] request) {
  int spaceIndex = indexOf(request, (byte) 32);
  return new String(Arrays.copyOfRange(request, 0, spaceIndex));
}

//-----------------------------------------------------------------------------
public static int indexOf(byte[] array, byte value) {
  for (int i = 0; i < array.length; i++) {
    if (array[i] == value) {
      return i;
    }
  }
  return -1; // If the value is not found
}

//-----------------------------------------------------------------------------
public static byte[] fixContentLength(byte[] request) {
  if(countMatches(request, ("Content-Length: ").getBytes()) > 0) {
    int start         = getBodyStart(request);
    int contentLength = request.length - start;
    return setHeader(request, "Content-Length", Integer.toString(contentLength), true);
  }
  else {
    return request;
  }
}

//-----------------------------------------------------------------------------
public static byte[] setHeader(byte[] request, String header, String value, boolean tolerateMissing) {
  int[]                 offsets      = Utilities.getHeaderOffsets(request, header);
  ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
  
  try {
    outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]));
    outputStream.write((value).getBytes());
    outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
    return outputStream.toByteArray();
  }
  catch(IOException var7) {
    throw new RuntimeException("Req creation unexpectedly failed");
  }
  catch(NullPointerException var8) {
    if(tolerateMissing) {
      return request;
    }
    else {
      String builder =
        "header locating fail: " + header + "'" + new String((request)) + "'" + "Can't find the header: " + header;
      throw new RuntimeException(builder + var8);
    }
  }
}

//-----------------------------------------------------------------------------
public static int[] getHeaderOffsets(byte[] request, String header) {
  int i   = 0;
  int end = request.length;
  
  while(i < end) {
    int lineStart = i++;
    
    int spaceIndex = indexOf(request, (byte) 32, i, end);
    if (spaceIndex == -1) break; // Exit if space not found
    
    byte[] headerName      = Arrays.copyOfRange(request, lineStart, i - 2);
    int    headerValueStart = spaceIndex + i; //skip space character
    
    int lineEnd = indexOf(request, (byte) 10, headerValueStart, end); // Find end of line
    if (lineEnd == -1) break; // Exit if end of line not found
    
    if(i == end) {
      break;
    }
    
    String headerStr = new String(headerName);
    if (header.equals(headerStr)) {
      return new int[]{lineStart, headerValueStart, lineEnd - 1}; // Adjust lineEnd to exclude newline character
    }
    
    // Move to the next line
    i = lineEnd + 1;
    
    // Check for end of request
    if (i + 1 < end && request[i] == 13 && request[i + 1] == 10) {
      break;
    }
  }
  
  return null;
}

//-----------------------------------------------------------------------------
public static int countMatches(byte[] response, byte[] match) {
  int matches = 0;
  if(match.length < 4) {
    return matches;
  }
  else {
    for(int start = 0; start < response.length; start += match.length) {
      start = Utilities.indexOf(response, match, true, start, response.length);
      if(start == -1) {
        break;
      }
      
      ++matches;
    }
    
    return matches;
  }
}

//-----------------------------------------------------------------------------
public static int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
  for(int i = from; i < to - pattern.length + 1; ++i) {
    boolean found = true;
    for(int j = 0; j < pattern.length; ++j) {
      if((caseSensitive && data[i + j] != pattern[j]) ||
        (!caseSensitive && Character.toLowerCase(data[i + j]) != Character.toLowerCase(pattern[j]))) {
        found = false;
        break;
      }
    }
    if(found) return i;
  }
  return -1;
}

//-----------------------------------------------------------------------------
public static int indexOf(byte[] array, byte value, int start, int end) {
  for (int i = start; i < end; i++) {
    if (array[i] == value) {
      return i;
    }
  }
  return -1; // If the value is not found
}

//-----------------------------------------------------------------------------
public static boolean invertable(String value) {
  return !value.equals(invert(value));
}

//-----------------------------------------------------------------------------
public static Object invert(String value) {
  return switch(value) {
    case "true" -> false;
    case "false" -> true;
    case "1" -> 0;
    case "0" -> 1;
    default -> value;
  };
}

//-----------------------------------------------------------------------------
public static String randomString(int len) {
  StringBuilder sb = new StringBuilder(len);
  sb.append("ghijklmnopqrstuvwxyz".charAt(rnd.nextInt("ghijklmnopqrstuvwxyz".length())));
  
  for(int i = 1; i < len; ++i) {
    sb.append(
      "0123456789abcdefghijklmnopqrstuvwxyz".charAt(rnd.nextInt("0123456789abcdefghijklmnopqrstuvwxyz".length())));
  }
  
  return sb.toString();
}

//-----------------------------------------------------------------------------
public static String getBody(byte[] response) {
  if(response == null) {
    return "";
  }
  else {
    int    bodyStart = getBodyStart(response);
    return new String(Arrays.copyOfRange(response, bodyStart, response.length));
  }
}

//-----------------------------------------------------------------------------
public static String generateCanary() {
  return randomString(4 + rnd.nextInt(7)) + rnd.nextInt(9);
}

//-----------------------------------------------------------------------------
public static int parseArrayIndex(String key) {
  try {
    if(key.length() > 2 && key.startsWith("[") && key.endsWith("]")) {
      return Integer.parseInt(key.substring(1, key.length() - 1));
    }
  }
  catch(NumberFormatException var2) {
  }
  
  return -1;
}

//-----------------------------------------------------------------------------
public static boolean isHTTP2(byte[] request) {
  int carriageReturnIndex = indexOf(request, (byte) 13);
  if (carriageReturnIndex < 6) {
    // Not enough characters before carriage return or failed to retrieve index
    return false;
  }
  
  String version = new String(Arrays.copyOfRange(request, carriageReturnIndex - 6, carriageReturnIndex));
  return "HTTP/2".equals(version);
}

//-----------------------------------------------------------------------------
public static byte[] replaceFirst(byte[] request, byte[] find, byte[] replace) {
  return replace(request, find, replace, 1);
}

//-----------------------------------------------------------------------------
public static byte[] appendToQuery(byte[] request, String suffix) {
  String url = getPathFromRequest(request);
  if(url.contains("?")) {
    if(url.indexOf("?") != url.length() - 1) {
      suffix = "&" + suffix;
    }
  }
  else {
    suffix = "?" + suffix;
  }
  
  return replaceFirst(request, url.getBytes(), (url + suffix).getBytes());
}

//-----------------------------------------------------------------------------
public static String getPathFromRequest(byte[] request) {
  int     i         = 0;
  boolean recording = false;
  
  StringBuilder path;
  for(path = new StringBuilder(); i < request.length; ++i) {
    byte x = request[i];
    if(recording) {
      if(x == 32) {
        break;
      }
      
      path.append((char) x);
    }
    else if(x == 32) {
      recording = true;
    }
  }
  
  return path.toString();
}

//-----------------------------------------------------------------------------
public static boolean isResponse(byte[] data) {
  byte[] start = Arrays.copyOfRange(data, 0, 5);
  return new String((start)).equals("HTTP/");
}

//-----------------------------------------------------------------------------
public static byte[] convertToHttp1(byte[] req) {
  String tmp = new String(req, StandardCharsets.ISO_8859_1);
  tmp = tmp.replaceFirst("HTTP/2", "HTTP/1.1");
  return tmp.getBytes(StandardCharsets.ISO_8859_1);
}

//-----------------------------------------------------------------------------
public static URL getURL(IHttpRequestResponse request) {
  return getURL(request.getRequest(), request.getHttpService());
}

//-----------------------------------------------------------------------------
public static URL getURL(byte[] request, IHttpService service) {
  URL url;
  try {
    url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request));
  }
  catch(MalformedURLException var4) {
    url = null;
  }
  
  return url;
}

//-----------------------------------------------------------------------------
public static byte[] replace(byte[] request, byte[] find, byte[] replace, int limit) {
  List<int[]> matches = getMatches(request, find, -1);
  if(limit != -1 && limit < matches.size()) {
    matches = matches.subList(0, limit);
  }
  
  if(matches.size() == 0) {
    return request;
  }
  else {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      
      for(int i = 0; i < matches.size(); ++i) {
        if(i == 0) {
          outputStream.write(Arrays.copyOfRange(request, 0, ((int[]) matches.get(i))[0]));
        }
        else {
          outputStream.write(Arrays.copyOfRange(request, ((int[]) matches.get(i - 1))[1], ((int[]) matches.get(i))[0]));
        }
        
        outputStream.write(replace);
        if(i == matches.size() - 1) {
          outputStream.write(Arrays.copyOfRange(request, ((int[]) matches.get(i))[1], request.length));
          break;
        }
      }
      
      request = outputStream.toByteArray();
      return request;
    }
    catch(IOException var7) {
      throw new UncheckedIOException(var7);
    }
  }
}


/////////////////////////////
// PUBLIC METHODS
/////////////////////////////
//-----------------------------------------------------------------------------
public void out(String message) {
  stdout.println(message);
}

//-----------------------------------------------------------------------------
public String getSetting(String name) {
  int    depth = StringUtils.countMatches(name, ".") + 1;
  String json  = callbacks.saveConfigAsJson(name);
  return json.split("\n")[depth].split(":", 2)[1];
}

//-----------------------------------------------------------------------------
public void showError(Exception e) {
  out("Error in thread: " + e.getMessage() + ". See error pane for stack trace.");
  e.printStackTrace(stderr);
}

//-----------------------------------------------------------------------------
public byte[] filterResponse(byte[] response) {
  if(response == null) {
    return new byte[] {110, 117, 108, 108};
  }
  else {
    IResponseInfo details          = helpers.analyzeResponse(response);
    String        inferredMimeType = details.getInferredMimeType();
    if(inferredMimeType.isEmpty()) {
      inferredMimeType = details.getStatedMimeType();
    }
    
    inferredMimeType = inferredMimeType.toLowerCase();
    byte[] filteredResponse;
    String headers;
    if(!inferredMimeType.contains("text") && !inferredMimeType.equals("html") && !inferredMimeType.contains("xml") &&
      !inferredMimeType.contains("script") && !inferredMimeType.contains("css") && !inferredMimeType.contains("json")) {
      headers          =
        helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset())) + details.getInferredMimeType();
      filteredResponse = helpers.stringToBytes(headers.toLowerCase());
    }
    else {
      filteredResponse = helpers.stringToBytes(helpers.bytesToString(response).toLowerCase());
    }
    
    if(details.getStatedMimeType().toLowerCase().contains("json") &&
      (inferredMimeType.contains("json") || inferredMimeType.contains("javascript"))) {
      headers = helpers.bytesToString(Arrays.copyOfRange(response, 0, details.getBodyOffset()));
      String body = helpers.bytesToString(Arrays.copyOfRange(response, details.getBodyOffset(), response.length));
      filteredResponse = helpers.stringToBytes(headers + StringEscapeUtils.unescapeJson(body));
    }
    
    return filteredResponse;
  }
}

//-----------------------------------------------------------------------------
public byte[] setMethod(byte[] request, String newMethod) {
  int i = 0;
  
  do {
    ++i;
  }while(request[i] != 32);
  
  ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
  
  try {
    outputStream.write(newMethod.getBytes());
    outputStream.write(Arrays.copyOfRange(request, i, request.length));
  }
  catch(IOException var5) {
  }
  
  return outputStream.toByteArray();
}

//-----------------------------------------------------------------------------
public void err(String message) {
  stderr.println(message);
}

//-----------------------------------------------------------------------------
public byte[] appendToHeader(byte[] request, String header, String value) {
  String baseValue = getHeader(request, header);
  return "".equals(baseValue) ? request : addOrReplaceHeader(request, header, baseValue + value);
}

//-----------------------------------------------------------------------------
public ArrayList<PartialParam> getQueryParams(byte[] request) {
  ArrayList<PartialParam> params = new ArrayList<>();
  if(request.length == 0) {
    return params;
  }
  else {
    int i = 0;
    
    while(request[i] != 63) {
      ++i;
      if(i == request.length) {
        return params;
      }
    }
    
    ++i;
    
    StringBuilder name;
    int           c;
    int           valueEnd;
    for(; request[i] != 32; params.add(new PartialParam(name.toString(), c, valueEnd, (byte) 0))) {
      for(name = new StringBuilder(); request[i] != 32; ++i) {
        c = (char) request[i];
        if(c == 61) {
          ++i;
          break;
        }
        
        name.append((char) c);
      }
      
      c = i;
      
      while(true) {
        char ch = (char) request[i];
        if(ch == '&') {
          valueEnd = i++;
          break;
        }
        
        if(ch == ' ') {
          valueEnd = i;
          break;
        }
        
        ++i;
      }
    }
    
    return params;
  }
}

//-----------------------------------------------------------------------------
public byte[] setHeader(byte[] request, String header, String value) {
  return setHeader(request, header, value, false);
}

//-----------------------------------------------------------------------------
public PartialParam paramify(byte[] request, String name, String target) {
  int start = Utilities.indexOf(request, target.getBytes(), true, 0, request.length);
  if(start == -1) {
    throw new RuntimeException("Failed to find target");
  }
  else {
    int end = start + target.length();
    return new PartialParam(name, start, end);
  }
}

//-----------------------------------------------------------------------------
public byte[] addOrReplaceHeader(byte[] request, String header, String value) {
  return getHeaderOffsets(request, header) != null ? setHeader(request, header, value)
    : replaceFirst(request, "\r\n\r\n".getBytes(), ("\r\n" + header + ": " + value + "\r\n\r\n").getBytes());
}

//-----------------------------------------------------------------------------
public boolean isBurpPro() {
  return callbacks.getBurpVersion()[0].contains("Professional");
}

//-----------------------------------------------------------------------------
public String getNameFromType(byte type) {
  switch(type) {
  case 0:
    return "url";
  case 1:
    return "body";
  case 2:
    return "cookie";
  case 3:
  case 4:
  case 5:
  default:
    return "unknown";
  case 6:
    return "json";
  case 7:
    return "header";
  }
}

//-----------------------------------------------------------------------------
public int generate(int seed, int count, List<String> accumulator) {
  int num = seed;
  
  for(int limit = seed + count; num < limit; ++num) {
    String word = num2word(num);
    if(word != null) {
      accumulator.add(word);
    }
    else {
      ++limit;
    }
  }
  
  return num;
}



//-----------------------------------------------------------------------------
public boolean similarIsh(Attack noBreakGroup, Attack breakGroup, Attack noBreak, Attack doBreak) {
  Iterator<String> var4 = noBreakGroup.getPrint().keySet().iterator();
  
  while(true) {
    String key;
    Object noBreakVal;
    do {
      if(!var4.hasNext()) {
        var4 = breakGroup.getPrint().keySet().iterator();
        
        do {
          if(!var4.hasNext()) {
            return true;
          }
          
          key = (String) var4.next();
        }while(noBreakGroup.getPrint().containsKey(key) ||
          breakGroup.getPrint().get(key).equals(noBreak.getPrint().get(key)));
        
        return false;
      }
      
      key        = (String) var4.next();
      noBreakVal = noBreakGroup.getPrint().get(key);
    }while(key.equals("input_reflections") && noBreakVal.equals(-3));
    
    if(!breakGroup.getPrint().containsKey(key)) {
      if(!noBreakVal.equals(doBreak.getPrint().get(key))) {
        return false;
      }
    }
    else if(!noBreakVal.equals(breakGroup.getPrint().get(key))) {
      return false;
    }
  }
}

//-----------------------------------------------------------------------------
public boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
  Iterator<String> var2 = doNotBreakAttackGroup.getPrint().keySet().iterator();
  
  String key;
  do {
    if(!var2.hasNext()) {
      return true;
    }
    
    key = (String) var2.next();
    if(!individualBreakAttack.getPrint().containsKey(key)) {
      return false;
    }
  }while(!individualBreakAttack.getPrint().containsKey(key) ||
    individualBreakAttack.getPrint().get(key).equals(doNotBreakAttackGroup.getPrint().get(key)));
  
  return false;
}

//-----------------------------------------------------------------------------
public boolean identical(Attack candidate, Attack attack2) {
  return candidate != null && candidate.getPrint().equals(attack2.getPrint());
}

//-----------------------------------------------------------------------------
public String getExtension(byte[] request) {
  String url         = getPathFromRequest(request);
  int    query_start = url.indexOf(63);
  if(query_start == -1) {
    query_start = url.length();
  }
  
  url = url.substring(0, query_start);
  int last_dot = url.lastIndexOf(46);
  return last_dot == -1 ? "" : url.substring(last_dot);
}

//-----------------------------------------------------------------------------
public byte[] replace(byte[] request, String find, String replace) {
  return replace(request, find.getBytes(), replace.getBytes());
}

//-----------------------------------------------------------------------------
public byte[] replace(byte[] request, byte[] find, byte[] replace) {
  return replace(request, find, replace, -1);
}

//-----------------------------------------------------------------------------
public byte[] replaceFirst(byte[] request, String find, String replace) {
  return replace(request, find.getBytes(), replace.getBytes(), 1);
}

//-----------------------------------------------------------------------------
public byte[] setBody(byte[] req, String body) {
  try {
    ByteArrayOutputStream synced = new ByteArrayOutputStream();
    synced.write(Arrays.copyOfRange(req, 0, getBodyStart(req)));
    synced.write(body.getBytes());
    return synced.toByteArray();
  }
  catch(IOException var3) {
    return null;
  }
}

//-----------------------------------------------------------------------------
public byte[] appendToPath(byte[] request, String suffix) {
  if (suffix != null && !suffix.isEmpty()) {
    int lineEndIndex = indexOf(request, (byte) 10); // \n
    if (lineEndIndex == -1) {
      return request; // No line end found
    }
    
    int queryIndex = indexOf(request, (byte) 63); // ?
    if (queryIndex == -1 || queryIndex >= lineEndIndex) {
      // No query string found
      request = replace(request, " HTTP/".getBytes(), (suffix + " HTTP/").getBytes());
    } else {
      // Query string found before the line end
      request = replace(request, "?".getBytes(), (suffix + "?").getBytes());
    }
  }
  return request;
}


//-----------------------------------------------------------------------------
public String fuzzSuffix() {
  return globalSettings.getBoolean("fuzz detect") ? "<a`'\"${{\\" : "";
}

//-----------------------------------------------------------------------------
public String toCanary(String payload) {
  return globalSettings.getString("canary") + mangle(payload);
}

//-----------------------------------------------------------------------------
public String mangle(String seed) {
  Random        seededRandom = new Random(seed.hashCode());
  StringBuilder sb           = new StringBuilder(7);
  sb.append("ghijklmnopqrstuvwxyz".charAt(seededRandom.nextInt("ghijklmnopqrstuvwxyz".length())));
  
  for(int i = 1; i < 8; ++i) {
    sb.append("0123456789abcdefghijklmnopqrstuvwxyz".charAt(
      seededRandom.nextInt("0123456789abcdefghijklmnopqrstuvwxyz".length())));
  }
  
  return sb.toString();
}

//-----------------------------------------------------------------------------
public String encodeParam(String payload) {
  return payload.replace("%", "%25").replace("\u0000", "%00").replace("&", "%26").replace("#", "%23")
    .replace(" ", "%20").replace(";", "%3b").replace("+", "%2b").replace("\n", "%0A").replace("\r", "%0d");
}

//-----------------------------------------------------------------------------
public byte[] addCacheBuster(byte[] req, String cacheBuster) {
  if(cacheBuster != null) {
    req = appendToQuery(req, cacheBuster + "=1");
  }
  else {
    cacheBuster = generateCanary();
  }
  
  if(globalSettings.getBoolean("include origin in cachebusters")) {
    req = addOrReplaceHeader(req, "Origin", "https://" + cacheBuster + ".com");
  }
  
  if(globalSettings.getBoolean("include path in cachebusters")) {
    String path = getPathFromRequest(req);
    path = "/" + cacheBuster + "/.." + path;
    req  = setPath(req, path);
  }
  
  req = appendToHeader(req, "Accept", ", text/" + cacheBuster);
  req = appendToHeader(req, "Accept-Encoding", ", " + cacheBuster);
  req = appendToHeader(req, "User-Agent", " " + cacheBuster);
  return req;
}

//-----------------------------------------------------------------------------
public boolean isHTTPS(IHttpService service) {
  return service.getProtocol().toLowerCase().contains("https");
}

//-----------------------------------------------------------------------------
public IRequestInfo analyzeRequest(byte[] request) {
  return new LazyRequestInfo(request);
}

//-----------------------------------------------------------------------------
public IHttpRequestResponse highlightRequestResponse(
  IHttpRequestResponse attack, String responseHighlight, String requestHighlight, IScannerInsertionPoint insertionPoint
) {
  List<int[]> requestMarkers = new ArrayList<>(1);
  if(requestHighlight != null && requestHighlight.length() > 2) {
    requestMarkers.add(insertionPoint.getPayloadOffsets(requestHighlight.getBytes()));
  }
  
  List<int[]> responseMarkers = new ArrayList<>(1);
  if(responseHighlight != null) {
    responseMarkers = getMatches(attack.getResponse(), responseHighlight.getBytes(), -1);
  }
  
  return callbacks.applyMarkers(attack, requestMarkers, responseMarkers);
}

//-----------------------------------------------------------------------------
public IHttpRequestResponse attemptRequest(IHttpService service, byte[] req) {
  return attemptRequest(service, req, false);
}

//-----------------------------------------------------------------------------
public IHttpRequestResponse attemptRequest(IHttpService service, byte[] req, boolean forceHttp1) {
  if(unloaded.get()) {
    out("Extension unloaded - aborting attack");
    throw new RuntimeException("Extension unloaded");
  }
  else {
    IHttpRequestResponse result               = null;
    int                  maxAttempts          = 3;
    boolean              expectNestedResponse = false;
    if(chopNestedResponses && "1".equals(getHeader(req, "X-Mine-Nested-Request"))) {
      expectNestedResponse = true;
      maxAttempts          = globalSettings.getInt("tunnelling retry count");
    }
    
    for(int attempt = 1; attempt < maxAttempts; ++attempt) {
      try {
          result = callbacks.makeHttpRequest(service, req, forceHttp1);
      }
      catch(RuntimeException var13) {
        err(var13.toString());
        err("Critical request error, retrying...");
        continue;
      }
      
      if(result.getResponse() == null) {
        err("Req failed, retrying...");
      }
      else {
        if(expectNestedResponse) {
          byte[] nestedResponse = getNestedResponse(result.getResponse());
          result.setResponse(nestedResponse);
          if(nestedResponse == null) {
            continue;
          }
        }
        break;
      }
    }
    
    if(result == null || result.getResponse() == null) {
      if(expectNestedResponse) {
        if(globalSettings.getBoolean("abort on tunnel failure")) {
          throw new RuntimeException("Failed to get a nested response after " + maxAttempts + " retries. Bailing!");
        }
        
        out("Failed to get a nested response after " + maxAttempts + " retries. Continuing with null response.");
      }
      else {
        out("Req failed multiple times, giving up");
      }
    }
    
    return result;
  }
}
//-----------------------------------------------------------------------------
public String getHeader(byte[] request, String header) {
  int[] offsets = getHeaderOffsets(request, header);
  if(offsets == null)
    return "";
  else
    return new String(Arrays.copyOfRange(request, offsets[1], offsets[2]), StandardCharsets.UTF_8);
}

//-----------------------------------------------------------------------------
public byte[] getBodyBytes(byte[] response) {
  if(response == null) {
    return null;
  }
  else {
    int bodyStart = getBodyStart(response);
    return Arrays.copyOfRange(response, bodyStart, response.length);
  }
}

//-----------------------------------------------------------------------------
public boolean containsBytes(byte[] request, byte[] value) {
  if(request == null) {
    return false;
  }
  else {
    return Utilities.indexOf(request, value, false, 0, request.length) != -1;
  }
}

//-----------------------------------------------------------------------------
public IScanIssue reportReflectionIssue(
  Attack[] attacks, IHttpRequestResponse baseRequestResponse, String title, String detail
) {
  IHttpRequestResponse[] requests  = new IHttpRequestResponse[attacks.length];
  Probe                  bestProbe = null;
  boolean                reliable  = false;
  detail = detail + "<br/><br/><b>Successful probes</b><br/>";
  String reportedSeverity = "High";
  int    evidenceCount    = 0;
  
  for(int i = 0; i < attacks.length; ++i) {
    requests[i] = attacks[i].getLastRequest();
    if(i % 2 == 0) {
      detail =
        detail + " &#160;  &#160; <table><tr><td><b>" + StringEscapeUtils.escapeHtml4(attacks[i].getProbe().getName()) +
          " &#160;  &#160; </b></td><td><b>" + StringEscapeUtils.escapeHtml4(attacks[i].payload) +
          " &#160; </b></td><td><b>";
    }
    else {
      detail = detail + StringEscapeUtils.escapeHtml4(attacks[i].payload) + "</b></td></tr>\n";
      HashMap<String, Object> workedPrint           = attacks[i].getLastPrint();
      HashMap<String, Object> consistentWorkedPrint = attacks[i].getPrint();
      HashMap<String, Object> breakPrint            = attacks[i - 1].getLastPrint();
      HashMap<String, Object> consistentBreakPrint  = attacks[i - 1].getPrint();
      Set<String>             allKeys               = new HashSet<>(consistentWorkedPrint.keySet());
      allKeys.addAll(consistentBreakPrint.keySet());
      String           boringDetail = "";
      Iterator<String> var16        = allKeys.iterator();

label73:
      while(true) {
        while(true) {
          String mark;
          String brokeResult;
          String workedResult;
          do {
            if(!var16.hasNext()) {
              detail = detail + boringDetail;
              detail = detail + "</table>\n";
              String tip = attacks[i].getProbe().getTip();
              if(!"".equals(tip)) {
                detail = detail + "&nbsp;<i>" + tip + "</i>";
              }
              break label73;
            }
            
            mark         = (String) var16.next();
            brokeResult  = breakPrint.get(mark).toString();
            workedResult = workedPrint.get(mark).toString();
          }while(brokeResult.equals(workedResult));
          
          ++evidenceCount;
          
          try {
            if(Math.abs(Integer.parseInt(brokeResult)) > 9999) {
              brokeResult = "X";
            }
            
            if(Math.abs(Integer.parseInt(workedResult)) > 9999) {
              workedResult = "Y";
            }
          }
          catch(NumberFormatException var21) {
            brokeResult  = StringEscapeUtils.escapeHtml4(brokeResult);
            workedResult = StringEscapeUtils.escapeHtml4(workedResult);
          }
          
          if(consistentBreakPrint.containsKey(mark) && consistentWorkedPrint.containsKey(mark)) {
            detail   =
              detail + "<tr><td>" + StringEscapeUtils.escapeHtml4(mark) + "</td><td>" + brokeResult + " </td><td>" +
                workedResult + "</td></tr>\n";
            reliable = true;
          }
          else if(consistentBreakPrint.containsKey(mark)) {
            boringDetail =
              boringDetail + "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark) + "</i></td><td><i>" + brokeResult +
                "</i></td><td><i> *" + workedResult + "*</i></td></tr>\n";
          }
          else {
            boringDetail =
              boringDetail + "<tr><td><i>" + StringEscapeUtils.escapeHtml4(mark) + "</i></td><td><i>*" + brokeResult +
                "*</i></td><td><i>" + workedResult + "</i></td></tr>\n";
          }
        }
      }
    }
    
    if(bestProbe == null || attacks[i].getProbe().getSeverity() >= bestProbe.getSeverity()) {
      bestProbe = attacks[i].getProbe();
      int severity = bestProbe.getSeverity();
      if(severity < 3) {
        reportedSeverity = "Low";
      }
      else if(severity < 7) {
        reportedSeverity = "Medium";
      }
    }
  }
  
  if(evidenceCount == 1) {
    reportedSeverity = "Information";
  }
  
  if("Interesting input handling".equals(title)) {
    title = bestProbe.getName();
  }
  
  return new Fuzzable(requests, baseRequestResponse, title, detail, reliable, reportedSeverity, this);
}

/////////////////////////////
// PRIVATE FIELDS
/////////////////////////////
private static final char[]               DIGITS            = new char[] {
  '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z'
};
private static final Random               rnd               = new Random();

private final PrintWriter stdout;
private final PrintWriter stderr;


/////////////////////////////
// PRIVATE FUNCTIONS
/////////////////////////////
//-----------------------------------------------------------------------------
private static List<int[]> getMatches(byte[] response, byte[] match, int giveUpAfter) {
  if(giveUpAfter == -1) {
    giveUpAfter = response.length;
  }
  
  if(match.length == 0) {
    throw new RuntimeException("Utilities.getMatches() on the empty string is not allowed)");
  }
  else {
    List<int[]> matches = new ArrayList<>();
    
    for(int start = 0; start < giveUpAfter; start += match.length) {
      start = Utilities.indexOf(response, match, true, start, giveUpAfter);
      if(start == -1) {
        break;
      }
      
      matches.add(new int[] {start, start + match.length});
    }
    
    return matches;
  }
}

//-----------------------------------------------------------------------------
private static String num2word(int num) {
  String number = num2String(num);
  return number.contains("0") ? null : number;
}

//-----------------------------------------------------------------------------
private static String num2String(int i) {
  if(i < 0) {
    throw new IllegalArgumentException("+ve integers only please");
  }
  else {
    char[] buf     = new char[7];
    int    charPos = 6;
    
    for(i = -i; i <= -DIGITS.length; i /= DIGITS.length) {
      buf[charPos--] = DIGITS[-(i % DIGITS.length)];
    }
    
    buf[charPos] = DIGITS[-i];
    return new String(buf, charPos, 7 - charPos);
  }
}

/////////////////////////////
// PRIVATE METHODS
/////////////////////////////
//-----------------------------------------------------------------------------
private byte[] setPath(byte[] request, String newPath) {
  String oldPath = getPathFromRequest(request);
  return replaceFirst(request, oldPath.getBytes(), newPath.getBytes());
}

//-----------------------------------------------------------------------------
private byte[] getNestedResponse(byte[] response) {
  byte[] body = getBodyBytes(response);
  if(!containsBytes(body, "HTTP/".getBytes())) {
    return null;
  }
  else {
    int nestedRespStart = helpers.indexOf(body, "HTTP/".getBytes(), true, 0, body.length);
    return Arrays.copyOfRange(body, nestedRespStart, body.length);
  }
}

}
