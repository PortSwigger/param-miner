package burp.model.param;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IParameter;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.Keysmith;
import burp.model.utilities.Utilities;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;


public class ParamGrabber implements IProxyListener, IHttpListener {

private final Utilities                 utilities;
private       Set<IHttpRequestResponse> savedJson      = ConcurrentHashMap.newKeySet();
    private HashSet<ArrayList<String>>  done           = new HashSet<>();
    private Set<String>                 savedGET       = ConcurrentHashMap.newKeySet();
    private Set<String>                 savedWords     = ConcurrentHashMap.newKeySet();
    private HashSet<String>             alreadyScanned = new HashSet<>();
    private ThreadPoolExecutor          taskEngine;

    public ParamGrabber(ThreadPoolExecutor taskEngine, Utilities utilities) {
      this.taskEngine = taskEngine;
      this.utilities  = utilities;
    }

    Set<IHttpRequestResponse> getSavedJson() {
        return savedJson;
    }
    Set<String> getSavedGET() {
        return savedGET;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && toolFlag != IBurpExtenderCallbacks.TOOL_EXTENDER) {
            addCacheBusters(messageInfo);
        }
    }

    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage messageInfo) {
        if (!messageIsRequest) {
            saveParams(messageInfo.getMessageInfo());
            launchScan(messageInfo.getMessageInfo());
        }
    }

    Set<String> getSavedWords() {
        return savedWords;
    }

    public void saveParams(IHttpRequestResponse baseRequestResponse) {
        // todo also use observed requests
        String body = utilities.getBody(baseRequestResponse.getResponse());
        if (!body.equals("")) {
            savedWords.addAll(getWords(utilities.helpers.bytesToString(baseRequestResponse.getResponse())));
            savedGET.addAll(getHtmlKeys(body));
            try {
                JsonParser parser = new JsonParser();
                JsonElement json = parser.parse(body);
                ArrayList<String> keys = Keysmith.getJsonKeys(json, new HashMap<>());
                if (!done.contains(keys)) {
                    //utilities.out("Importing observed data...");
                    done.add(keys);
                    savedJson.add(utilities.callbacks.saveBuffersToTempFiles(baseRequestResponse));
                }
            } catch (JsonParseException e) {

            }
        }
    }

    private void addCacheBusters(IHttpRequestResponse messageInfo) {
        byte[] placeHolder = utilities.helpers.stringToBytes("$randomplz");
        if (utilities.countMatches(messageInfo.getRequest(), placeHolder) > 0) {
            messageInfo.setRequest(
                    utilities.fixContentLength(utilities.replace(messageInfo.getRequest(), placeHolder, utilities.helpers.stringToBytes(utilities.generateCanary())))
            );
        }

        byte[] req = messageInfo.getRequest();
        String cacheBuster = null;
        if (utilities.globalSettings.getBoolean("Add dynamic cachebuster")) {
            cacheBuster = utilities.generateCanary();
        }
        else if (utilities.globalSettings.getBoolean("Add 'fcbz' cachebuster")) {
            cacheBuster = "fcbz";
        }

        if (cacheBuster != null) {
            req = utilities.addCacheBuster(req, cacheBuster);
        }

        messageInfo.setRequest(req);
    }

    private void launchScan(IHttpRequestResponse messageInfo) {
        if (!utilities.globalSettings.getBoolean("enable auto-mine")) {
            return;
        }

        IRequestInfo reqInfo = utilities.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        if (!utilities.callbacks.isInScope(reqInfo.getUrl())) {
            return;
        }

        IResponseInfo respInfo    = utilities.helpers.analyzeResponse(messageInfo.getResponse());
        StringBuilder codeBuidler = new StringBuilder();
        String contentType = respInfo.getStatedMimeType();

        codeBuidler.append(reqInfo.getUrl().getHost());
        codeBuidler.append(contentType);

        String broadCode = codeBuidler.toString();
        if (!alreadyScanned.contains(broadCode)){
            //utilities.out("Queueing headers+cookies on "+reqInfo.getUrl());
            if (utilities.globalSettings.getBoolean("auto-mine headers")) {
                taskEngine.execute(new ParamGuesser(utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, Utilities.PARAM_HEADER, this, taskEngine, utilities.globalSettings.getInt("rotation interval"), utilities.globalSettings, utilities));
            }
            if (utilities.globalSettings.getBoolean("auto-mine cookies")) {
                taskEngine.execute(new ParamGuesser(utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, IParameter.PARAM_COOKIE, this, taskEngine, utilities.globalSettings.getInt("rotation interval"), utilities.globalSettings, utilities));
            }

            alreadyScanned.add(broadCode);
        }

        if (!utilities.globalSettings.getBoolean("auto-mine params")) {
            return;
        }

        codeBuidler.append(
                reqInfo.getParameters().stream()
                    .map(IParameter::getName)
                    .collect(Collectors.joining(" "))
        );


        if(contentType.equals("JSON") || contentType.equals("HTML")) {
            codeBuidler.append(reqInfo.getUrl().getPath());
        }

        String paramCode = codeBuidler.toString();
        if (alreadyScanned.contains(paramCode)) {
            return;
        }

        byte guessType = IParameter.PARAM_URL;
        if (reqInfo.getMethod().equals("POST")) {
            guessType = IParameter.PARAM_BODY;
        }

        utilities.out("Queueing params on "+reqInfo.getUrl());
        taskEngine.execute(new ParamGuesser(utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, guessType, this, taskEngine, utilities.globalSettings.getInt("rotation interval"), utilities.globalSettings, utilities));
        alreadyScanned.add(paramCode);
    }
}
