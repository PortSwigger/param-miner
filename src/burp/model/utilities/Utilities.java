package burp.model.utilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.model.param.PartialParam;
import burp.view.ConfigurableSettings;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.lang3.CharUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.JFrame;
import java.awt.Frame;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class Utilities {
public AtomicInteger requestCount = new AtomicInteger(0);
public final  String        version      = "1.03";
public String                 name = "uninitialised";
public IBurpExtenderCallbacks callbacks;
public IExtensionHelpers      helpers;
public ConfigurableSettings   globalSettings;

public static int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
  for(int i = from; i < to - pattern.length + 1; ++i) {
    boolean found = true;
    for(int j = 0; j < pattern.length; ++j) {
      if ((caseSensitive && data[i+j] != pattern[j]) || (!caseSensitive && Character.toLowerCase(data[i+j]) != Character.toLowerCase(pattern[j]))) {
        found = false;
        break;
      }
    }
    if (found) return i;
  }
  return -1;
}

public String getSetting(String name) {
  int    depth = StringUtils.countMatches(name, ".") + 1;
  String json  = callbacks.saveConfigAsJson(name);
  String value = json.split("\n")[depth].split(":", 2)[1];
  return value;
}

public void showError(Exception e) {
  out("Error in thread: " + e.getMessage() + ". See error pane for stack trace.");
  e.printStackTrace(stderr);
}

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

public void doActiveScan(IHttpRequestResponse req, int[] offsets) {
  String           host       = helpers.analyzeRequest(req).getUrl().getHost();
  int              port       = helpers.analyzeRequest(req).getUrl().getPort();
  boolean          useHTTPS   = helpers.analyzeRequest(req).getUrl().toString().startsWith("https");
  ArrayList<int[]> offsetList = new ArrayList<>();
  offsetList.add(offsets);
  
  try {
    callbacks.doActiveScan(host, port, useHTTPS, req.getRequest(), offsetList);
  }
  catch(IllegalArgumentException var7) {
    err("Couldn't scan, bad insertion points: " + Arrays.toString(offsetList.get(0)));
  }
  
}

public void err(String message) {
  stderr.println(message);
}

public byte[] appendToHeader(byte[] request, String header, String value) {
  String baseValue = getHeader(request, header);
  return "".equals(baseValue) ? request : addOrReplaceHeader(request, header, baseValue + value);
}

public static String getMethod(byte[] request) {
  int i;
  for(i = 0; request[i] != 32; ++i) {
  }
  
  return new String(Arrays.copyOfRange(request, 0, i));
}

public ArrayList<PartialParam> getQueryParams(byte[] request) {
  ArrayList<PartialParam> params = new ArrayList();
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

public byte[] setHeader(byte[] request, String header, String value) {
  return setHeader(request, header, value, false);
}

public String encodeJSON(String input) {
  input = input.replace("\\", "\\\\");
  input = input.replace("\"", "\\\"");
  return input;
}

public PartialParam paramify(byte[] request, String name, String target, String fakeBaseValue) {
  int start = Utilities.indexOf(request, target.getBytes(), true, 0, request.length);
  if(start == -1) {
    throw new RuntimeException("Failed to find target");
  }
  else {
    int end = start + target.length();
    return new PartialParam(name, start, end);
  }
}

public byte[] addOrReplaceHeader(byte[] request, String header, String value) {
  return getHeaderOffsets(request, header) != null ? setHeader(request, header, value)
    : replaceFirst(request, "\r\n\r\n".getBytes(), ("\r\n" + header + ": " + value + "\r\n\r\n").getBytes());
}

public byte[] addOrReplaceHeaderOld(byte[] request, String header, String value) {
  try {
    int i   = 0;
    int end = request.length;
    
    while(i < end && request[i++] != 10) {
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    
    while(i < end) {
      int line_start = i;
      
      while(i < end && request[i++] != 32) {
      }
      
      byte[] header_name      = Arrays.copyOfRange(request, line_start, i - 2);
      int    headerValueStart = i;
      
      while(i < end && request[i++] != 10) {
      }
      
      if(i == end) {
        break;
      }
      
      if(i + 2 < end && request[i] == 13 && request[i + 1] == 10) {
        outputStream.write(Arrays.copyOfRange(request, 0, i));
        outputStream.write(helpers.stringToBytes(header + ": " + value + "\r\n"));
        outputStream.write(Arrays.copyOfRange(request, i, end));
        return outputStream.toByteArray();
      }
      
      String header_str = helpers.bytesToString(header_name);
      if(header.equals(header_str)) {
        outputStream.write(Arrays.copyOfRange(request, 0, headerValueStart));
        outputStream.write(helpers.stringToBytes(value));
        outputStream.write(Arrays.copyOfRange(request, i - 2, end));
        return outputStream.toByteArray();
      }
    }
    
    outputStream.write(Arrays.copyOfRange(request, 0, end - 2));
    outputStream.write(helpers.stringToBytes(header + ": " + value + "\r\n\r\n"));
    return outputStream.toByteArray();
  }
  catch(IOException var10) {
    throw new RuntimeException("Req creation unexpectedly failed");
  }
}

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
      String builder = "header locating fail: " + header +
        "'" + new String((request)) + "'" +
        "Can't find the header: " + header;
      throw new RuntimeException(builder + var8);
    }
  }
}
final         boolean                 DEBUG               = false;
static final        byte    CONFIRMATIONS       = 5;
public static final byte    PARAM_HEADER        = 7;
public static       boolean chopNestedResponses = false;
public        boolean supportsHTTP2       = true;
public        AtomicBoolean     unloaded     = new AtomicBoolean(false);
public static HashSet<String>   phpFunctions  = new HashSet();
public static ArrayList<String> paramNames     = new ArrayList();
public static HashSet<String>         boringHeaders  = new HashSet();
public static Set<String>             reportedParams = ConcurrentHashMap.newKeySet();
static        CircularFifoQueue<Long> requestTimes   = new CircularFifoQueue(100);
static               Random                  rnd                 = new Random();
static               ThreadLocal<Integer>    goAcceleratorPort   = new ThreadLocal();
static               AtomicInteger           nextPort            = new AtomicInteger(1901);

public Utilities(IBurpExtenderCallbacks incallbacks, HashMap<String, Object> settings, String name) {
  this.name      = name;
  callbacks      = incallbacks;
  stdout         = new PrintWriter(callbacks.getStdout(), true);
  stderr         = new PrintWriter(callbacks.getStderr(), true);
  helpers        = callbacks.getHelpers();
  out("Using albinowaxUtils v1.03");
  out(
    "This extension should be run on the latest version of Burp Suite. Using an older version of Burp may cause " +
      "impaired functionality.");
  if(settings != null) {
    globalSettings = new ConfigurableSettings(settings, this);
  }
  
}

public void out(String message) {
  stdout.println(message);
}

public JFrame getBurpFrame() {
  Frame[] var0 = Frame.getFrames();
  int     var1 = var0.length;
  
  for(int var2 = 0; var2 < var1; ++var2) {
    Frame f = var0[var2];
    if(f.isVisible() && f.getTitle().startsWith("Burp Suite")) {
      return (JFrame) f;
    }
  }
  
  return null;
}

public boolean isBurpPro() {
  return callbacks.getBurpVersion()[0].contains("Professional");
}

String getResource(String name) {
  return (new Scanner(Utilities.class.getResourceAsStream(name), "UTF-8")).useDelimiter("\\A").next();
}

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

private String num2word(int num) {
  String number = num2String(num);
  return number.contains("0") ? null : number;
}

private String num2String(int i) {
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

String filter(String input, String safeChars) {
  StringBuilder      out     = new StringBuilder(input.length());
  HashSet<Character> charset = new HashSet();
  charset.addAll(safeChars.chars().mapToObj((cx)->{
    return (char) cx;
  }).collect(Collectors.toList()));
  char[] var4 = input.toCharArray();
  int    var5 = var4.length;
  
  for(int var6 = 0; var6 < var5; ++var6) {
    char c = var4[var6];
    if(charset.contains(c)) {
      out.append(c);
    }
  }
  
  return out.toString();
}

boolean mightBeOrderBy(String name, String value) {
  return name.toLowerCase().contains("order") || name.toLowerCase().contains("sort") ||
    value.equalsIgnoreCase("asc") || value.equalsIgnoreCase("desc") ||
    StringUtils.isNumeric(value) && Double.parseDouble(value) <= 1000.0 ||
    value.length() < 20 && StringUtils.isAlpha(value);
}

boolean mightBeIdentifier(String value) {
  for(int i = 0; i < value.length(); ++i) {
    char x = value.charAt(i);
    if(!CharUtils.isAsciiAlphanumeric(x) && x != '.' && x != '-' && x != '_' && x != ':' && x != '$') {
      return false;
    }
  }
  
  return true;
}

Attack buildTransformationAttack(
  IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, String leftAnchor, String payload,
  String rightAnchor
) {
  IHttpRequestResponse req = attemptRequest(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(
    helpers.stringToBytes(insertionPoint.getBaseValue() + leftAnchor + payload + rightAnchor)));
  return new Attack(
    highlightRequestResponse(req, leftAnchor, leftAnchor + payload + rightAnchor, insertionPoint), null,
    payload, "", this
  );
}

public IHttpRequestResponse highlightRequestResponse(
  IHttpRequestResponse attack, String responseHighlight, String requestHighlight, IScannerInsertionPoint insertionPoint
) {
  List<int[]> requestMarkers = new ArrayList(1);
  if(requestHighlight != null && requestHighlight.length() > 2) {
    requestMarkers.add(insertionPoint.getPayloadOffsets(requestHighlight.getBytes()));
  }
  
  List<int[]> responseMarkers = new ArrayList(1);
  if(responseHighlight != null) {
    responseMarkers = getMatches(attack.getResponse(), responseHighlight.getBytes(), -1);
  }
  
  return callbacks.applyMarkers(attack, requestMarkers, responseMarkers);
}

static List<int[]> getMatches(byte[] response, byte[] match, int giveUpAfter) {
  if(giveUpAfter == -1) {
    giveUpAfter = response.length;
  }
  
  if(match.length == 0) {
    throw new RuntimeException("Utilities.getMatches() on the empty string is not allowed)");
  }
  else {
    List<int[]> matches = new ArrayList();
    
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

public IHttpRequestResponse attemptRequest(IHttpService service, byte[] req) {
  return attemptRequest(service, req, false);
}

public IHttpRequestResponse attemptRequest(IHttpService service, byte[] req, boolean forceHttp1) {
  if(unloaded.get()) {
    out("Extension unloaded - aborting attack");
    throw new RuntimeException("Extension unloaded");
  }
  else {
    boolean              LOG_PERFORMANCE      = false;
    boolean              GO_ACCELERATOR       = false;
    IHttpRequestResponse result               = null;
    long                 start                = 0L;
    int                  maxAttempts          = 3;
    boolean              expectNestedResponse = false;
    if(chopNestedResponses && "1".equals(getHeader(req, "X-Mine-Nested-Request"))) {
      expectNestedResponse = true;
      maxAttempts          = globalSettings.getInt("tunnelling retry count");
    }
    
    for(int attempt = 1; attempt < maxAttempts; ++attempt) {
      try {
        if(LOG_PERFORMANCE) {
          requestCount.incrementAndGet();
          start = System.currentTimeMillis();
        }
        
        if(GO_ACCELERATOR) {
          result = fetchWithGo(service, req);
        }
        else {
          result = callbacks.makeHttpRequest(service, req, forceHttp1);
        }
      }
      catch(RuntimeException var13) {
        RuntimeException e = var13;
        log(e.toString());
        log("Critical request error, retrying...");
        continue;
      }
      
      if(result.getResponse() == null) {
        log("Req failed, retrying...");
      }
      else {
        if(expectNestedResponse) {
          byte[] nestedResponse = getNestedResponse(result.getResponse());
          result.setResponse(nestedResponse);
          if(nestedResponse == null) {
            continue;
          }
        }
        
        if(LOG_PERFORMANCE) {
          long duration = System.currentTimeMillis() - start;
          out("Time: " + duration);
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
        log("Req failed multiple times, giving up");
      }
    }
    
    return result;
  }
}

public void log(String message) {
}

public String getHeader(byte[] request, String header) {
  int[] offsets = getHeaderOffsets(request, header);
  if(offsets == null) {
    return "";
  }
  else {
    String value = helpers.bytesToString(Arrays.copyOfRange(request, offsets[1], offsets[2]));
    return value;
  }
}

public static int[] getHeaderOffsets(byte[] request, String header) {
  int i   = 0;
  int end = request.length;
  
  while(i < end) {
    int line_start = i++;
    
    while(i < end && request[i++] != 32) {
    }
    
    byte[] header_name      = Arrays.copyOfRange(request, line_start, i - 2);
    int    headerValueStart = i;
    
    while(i < end && request[i++] != 10) {
    }
    
    if(i == end) {
      break;
    }
    
    String header_str = new String(header_name);
    if(header.equals(header_str)) {
      int[] offsets = new int[] {line_start, headerValueStart, i - 2};
      return offsets;
    }
    
    if(i + 2 < end && request[i] == 13 && request[i + 1] == 10) {
      break;
    }
  }
  
  return null;
}

IHttpRequestResponse fetchWithGo(IHttpService service, byte[] req) {
  int port = goAcceleratorPort.get();
  if(port == 0) {
    goAcceleratorPort.set(nextPort.getAndIncrement());
  }
  
  try {
    out("Routing request to " + port);
    Socket sock           = new Socket("127.0.0.1", port);
    String preppedService = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    sock.getOutputStream()
      .write((preppedService + "\u0000|\u0000" + helpers.bytesToString(req) + "\u0000|\u0000").getBytes());
    byte[]                readBuffer = new byte[4096];
    ByteArrayOutputStream response   = new ByteArrayOutputStream();
    
    while(true) {
      int read = sock.getInputStream().read(readBuffer);
      if(read == -1) {
        throw new RuntimeException("oh dear");
      }
      
      response.write(Arrays.copyOfRange(readBuffer, 0, read));
    }
  }
  catch(Exception var8) {
    out("oh dear");
    return null;
  }
}

byte[] getNestedResponse(byte[] response) {
  byte[] body = getBodyBytes(response);
  if(!containsBytes(body, "HTTP/".getBytes())) {
    return null;
  }
  else {
    int nestedRespStart = helpers.indexOf(body, "HTTP/".getBytes(), true, 0, body.length);
    return Arrays.copyOfRange(body, nestedRespStart, body.length);
  }
}

public byte[] getBodyBytes(byte[] response) {
  if(response == null) {
    return null;
  }
  else {
    int bodyStart = getBodyStart(response);
    return Arrays.copyOfRange(response, bodyStart, response.length);
  }
}

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

public boolean containsBytes(byte[] request, byte[] value) {
  if(request == null) {
    return false;
  }
  else {
    return helpers.indexOf(request, value, false, 0, request.length) != -1;
  }
}

boolean isInPath(IScannerInsertionPoint insertionPoint) {
  byte    type     = insertionPoint.getInsertionPointType();
  boolean isInPath = type == 37 || type == 33;
  if(!isInPath && type == 64) {
    String injectionCanary = "zxcvcxz";
    String path            = getPathFromRequest(insertionPoint.buildRequest("zxcvcxz".getBytes()));
    if(path.contains("zxcvcxz")) {
      if(path.contains("?")) {
        if(path.indexOf("zxcvcxz") < path.indexOf("?")) {
          isInPath = true;
        }
      }
      else {
        isInPath = true;
      }
    }
  }
  
  return isInPath;
}

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

public static boolean invertable(String value) {
  return !value.equals(invert(value));
}

public static Object invert(String value) {
  if(value != null) {
    if(value.equals("true")) {
      return false;
    }
    
    if(value.equals("false")) {
      return true;
    }
    
    if(value.equals("1")) {
      return 0;
    }
    
    if(value.equals("0")) {
      return 1;
    }
  }
  
  return value;
}

public static String randomString(int len) {
  StringBuilder sb = new StringBuilder(len);
  sb.append("ghijklmnopqrstuvwxyz".charAt(rnd.nextInt("ghijklmnopqrstuvwxyz".length())));
  
  for(int i = 1; i < len; ++i) {
    sb.append(
      "0123456789abcdefghijklmnopqrstuvwxyz".charAt(rnd.nextInt("0123456789abcdefghijklmnopqrstuvwxyz".length())));
  }
  
  return sb.toString();
}

public boolean similarIsh(Attack noBreakGroup, Attack breakGroup, Attack noBreak, Attack doBreak) {
  Iterator var4 = noBreakGroup.getPrint().keySet().iterator();
  
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

public boolean similar(Attack doNotBreakAttackGroup, Attack individualBreakAttack) {
  Iterator var2 = doNotBreakAttackGroup.getPrint().keySet().iterator();
  
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

boolean verySimilar(Attack attack1, Attack attack2) {
  if(!attack1.getPrint().keySet().equals(attack2.getPrint().keySet())) {
    return false;
  }
  else {
    Iterator var2 = attack1.getPrint().keySet().iterator();
    
    String key;
label31:
    do {
      while(var2.hasNext()) {
        key = (String) var2.next();
        if(!key.equals("input_reflections") ||
          !attack1.getPrint().get(key).equals(-3) && !attack2.getPrint().get(key).equals(-3)) {
          continue label31;
        }
      }
      
      return true;
    }while(!attack2.getPrint().containsKey(key) || attack2.getPrint().get(key).equals(attack1.getPrint().get(key)));
    
    return false;
  }
}

public boolean identical(Attack candidate, Attack attack2) {
  return candidate != null && candidate.getPrint().equals(attack2.getPrint());
}

public static String getBody(byte[] response) {
  if(response == null) {
    return "";
  }
  else {
    int    bodyStart = getBodyStart(response);
    String body      = new String(Arrays.copyOfRange(response, bodyStart, response.length));
    return body;
  }
}

public static String generateCanary() {
  return randomString(4 + rnd.nextInt(7)) + rnd.nextInt(9);
}

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

boolean mightBeFunction(String value) {
  return phpFunctions.contains(value);
}

byte[] setPath(byte[] request, String newPath) {
  String oldPath = getPathFromRequest(request);
  return replaceFirst(request, oldPath.getBytes(), newPath.getBytes());
}

public static boolean isHTTP2(byte[] request) {
  int i;
  for(i = 0; i < request.length && request[i] != 13; ++i) {
  }
  
  return i >= 6 && "HTTP/2".equals(new String(Arrays.copyOfRange(request, i - 6, i)));
}

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

public byte[] replace(byte[] request, String find, String replace) {
  return replace(request, find.getBytes(), replace.getBytes());
}

public byte[] replace(byte[] request, byte[] find, byte[] replace) {
  return replace(request, find, replace, -1);
}

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

public IHttpRequestResponse fetchFromSitemap(URL url) {
  IHttpRequestResponse[] pages = callbacks.getSiteMap(sensibleURL(url));
  IHttpRequestResponse[] var2  = pages;
  int                    var3  = pages.length;
  
  for(int var4 = 0; var4 < var3; ++var4) {
    IHttpRequestResponse page = var2[var4];
    if(page.getResponse() != null && url.equals(getURL(page))) {
      return page;
    }
  }
  
  return null;
}

public String sensibleURL(URL url) {
  String out = url.toString();
  if(url.getDefaultPort() == url.getPort()) {
    out = out.replaceFirst(":" + url.getPort(), "");
  }
  
  return out;
}

public static URL getURL(IHttpRequestResponse request) {
  return getURL(request.getRequest(), request.getHttpService());
}

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

public int countByte(byte[] response, byte match) {
  int count = 0;
  
  for(int i = 0; i < response.length; ++i) {
    if(response[i] == match) {
      ++count;
    }
  }
  
  return count;
}

public int countMatches(Resp response, String match) {
  byte[] resp = response.getReq().getResponse();
  return resp != null && resp.length != 0 ? countMatches(resp, match.getBytes()) : 0;
}

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

public byte[] replaceFirst(byte[] request, String find, String replace) {
  return replace(request, find.getBytes(), replace.getBytes(), 1);
}

public static byte[] replaceFirst(byte[] request, byte[] find, byte[] replace) {
  return replace(request, find, replace, 1);
}

public byte[] appendToQueryzzz(byte[] request, String suffix) {
  if(suffix != null && !suffix.equals("")) {
    int lineEnd = 0;
    
    while(lineEnd < request.length && request[lineEnd++] != 10) {
    }
    
    int queryStart = 0;
    
    while(queryStart < lineEnd && request[queryStart++] != 63) {
    }
    
    if(queryStart >= lineEnd) {
      suffix = "?" + suffix;
    }
    else {
      suffix = "&";
    }
    
    return replace(request, " HTTP/".getBytes(), (suffix + " HTTP/").getBytes());
  }
  else {
    return request;
  }
}

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

public byte[] appendToPath(byte[] request, String suffix) {
  if(suffix != null && !suffix.equals("")) {
    int i = 0;
    
    while(i < request.length && request[i++] != 10) {
    }
    
    int j = 0;
    
    while(j < i && request[j++] != 63) {
    }
    
    if(j >= i) {
      request = replace(request, " HTTP/".getBytes(), (suffix + " HTTP/").getBytes());
    }
    else {
      request = replace(request, "?".getBytes(), (suffix + "?").getBytes());
    }
    
    return request;
  }
  else {
    return request;
  }
}

public String fuzzSuffix() {
  return globalSettings.getBoolean("fuzz detect") ? "<a`'\"${{\\" : "";
}

public String toCanary(String payload) {
  return globalSettings.getString("canary") + mangle(payload);
}

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

String getStartType(byte[] response) {
  int    i     = getBodyStart(response);
  String start = "";
  if(i == response.length) {
    start = "[blank]";
  }
  else if(response[i] == 60) {
    while(i < response.length && response[i] != 32 && response[i] != 10 && response[i] != 13 && response[i] != 62) {
      start = start + (char) (response[i] & 255);
      ++i;
    }
  }
  else {
    start = "text";
  }
  
  return start;
}

boolean contains(Resp response, String match) {
  byte[] resp = response.getReq().getResponse();
  if(resp != null && resp.length != 0) {
    return helpers.indexOf(resp, match.getBytes(), false, 0, resp.length) != -1;
  }
  else {
    return false;
  }
}

public static boolean isResponse(byte[] data) {
  byte[] start = Arrays.copyOfRange(data, 0, 5);
  return new String((start)).equals("HTTP/");
}

List<IParameter> getExtraInsertionPoints(byte[] request) {
  List<IParameter> params = new ArrayList();
  int              end    = getBodyStart(request);
  int              i      = 0;
  
  while(i < end && request[i++] != 32) {
  }
  
  while(i < end) {
    byte c = request[i];
    if(c == 32 || c == 63 || c == 35) {
      break;
    }
    
    ++i;
  }
  
  params.add(new PartialParam("path", i, i));
  
  while(request[i++] != 10 && i < end) {
  }
  
  String[] to_poison = new String[] {"User-Agent", "Referer", "X-Forwarded-For", "Host"};
  params.addAll(getHeaderInsertionPoints(request, to_poison));
  return params;
}

List<IParameter> getHeaderInsertionPoints(byte[] request, String[] to_poison) {
  List<IParameter> params = new ArrayList();
  int              end    = getBodyStart(request);
  int              i      = 0;
  
  while(request[i++] != 10 && i < end) {
  }
  
  while(i < end) {
    int line_start = i;
    
    while(i < end && request[i++] != 32) {
    }
    
    byte[] header_name      = Arrays.copyOfRange(request, line_start, i - 2);
    int    headerValueStart = i;
    
    while(i < end && request[i++] != 10) {
    }
    
    if(i == end) {
      break;
    }
    
    String   header_str = helpers.bytesToString(header_name);
    String[] var9       = to_poison;
    int      var10      = to_poison.length;
    
    for(int var11 = 0; var11 < var10; ++var11) {
      String header = var9[var11];
      if(header.equals(header_str)) {
        params.add(new PartialParam(header, headerValueStart, i - 2));
      }
    }
  }
  
  return params;
}

boolean isHTTP(URL url) {
  String protocol = url.getProtocol().toLowerCase();
  return "https".equals(protocol);
}

public static byte[] convertToHttp1(byte[] req) {
  String tmp = new String(req, StandardCharsets.ISO_8859_1);
  tmp = tmp.replaceFirst("HTTP/2", "HTTP/1.1");
  return tmp.getBytes(StandardCharsets.ISO_8859_1);
}

public String encodeParam(String payload) {
  return payload.replace("%", "%25").replace("\u0000", "%00").replace("&", "%26").replace("#", "%23")
    .replace(" ", "%20").replace(";", "%3b").replace("+", "%2b").replace("\n", "%0A").replace("\r", "%0d");
}

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

public boolean isHTTPS(IHttpService service) {
  return service.getProtocol().toLowerCase().contains("https");
}

public IRequestInfo analyzeRequest(byte[] request) {
  return analyzeRequest(request, null);
}

IRequestInfo analyzeRequest(byte[] request, IHttpService service) {
  return new LazyRequestInfo(request, service);
}

IRequestInfo analyzeRequest(IHttpRequestResponse request) {
  return analyzeRequest(request.getRequest(), request.getHttpService());
}

IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse) {
  return reportReflectionIssue(attacks, baseRequestResponse, "", "");
}

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
      Set<String>             allKeys               = new HashSet(consistentWorkedPrint.keySet());
      allKeys.addAll(consistentBreakPrint.keySet());
      String   boringDetail = "";
      Iterator var16        = allKeys.iterator();

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

IScanIssue reportReflectionIssue(Attack[] attacks, IHttpRequestResponse baseRequestResponse, String title) {
  return reportReflectionIssue(attacks, baseRequestResponse, title, "");
}
private final String                  CHARSET             = "0123456789abcdefghijklmnopqrstuvwxyz";
private final String                  START_CHARSET       = "ghijklmnopqrstuvwxyz";
private       PrintWriter             stdout;
private       PrintWriter stderr;
private final char[]      DIGITS = new char[] {
  '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z'
};
}
