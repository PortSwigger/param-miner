package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;


public class ParamGrabber implements IProxyListener, IHttpListener {

    private Set<IHttpRequestResponse> savedJson = ConcurrentHashMap.newKeySet();
    private HashSet<ArrayList<String>> done = new HashSet<>();
    private Set<String> savedGET  = ConcurrentHashMap.newKeySet();
    private Set<String> savedWords  = ConcurrentHashMap.newKeySet();
    private HashSet<String> alreadyScanned = new HashSet<>();
    private ThreadPoolExecutor taskEngine;

    ParamGrabber(ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
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

    void saveParams(IHttpRequestResponse baseRequestResponse) {
        // todo also use observed requests
        String body = BulkUtilities.getBody(baseRequestResponse.getResponse());
        if (!body.equals("")) {
            savedWords.addAll(getWords(BulkUtilities.helpers.bytesToString(baseRequestResponse.getResponse())));
            savedGET.addAll(getHtmlKeys(body));
            try {
                JsonParser parser = new JsonParser();
                JsonElement json = parser.parse(body);
                ArrayList<String> keys = Keysmith.getJsonKeys(json, new HashMap<>());
                if (!done.contains(keys)) {
                    //BulkUtilities.out("Importing observed data...");
                    done.add(keys);
                    savedJson.add(BulkUtilities.callbacks.saveBuffersToTempFiles(baseRequestResponse));
                }
            } catch (JsonParseException e) {

            }
        }
    }

    private void addCacheBusters(IHttpRequestResponse messageInfo) {
        byte[] placeHolder = BulkUtilities.helpers.stringToBytes("$randomplz");
        if (BulkUtilities.countMatches(messageInfo.getRequest(), placeHolder) > 0) {
            messageInfo.setRequest(
                    BulkUtilities.replace(messageInfo.getRequest(), placeHolder, BulkUtilities.helpers.stringToBytes(BulkUtilities.randomString(10)))
            );
        }

        byte[] req = messageInfo.getRequest();
        String cacheBuster = null;
        if (BulkUtilities.globalSettings.getBoolean("Add dynamic cachebuster")) {
            cacheBuster = BulkUtilities.generateCanary();
        }
        else if (BulkUtilities.globalSettings.getBoolean("Add 'fcbz' cachebuster")) {
            cacheBuster = "fcbz";
        }

        if (cacheBuster != null) {
            req = BulkUtilities.addCacheBuster(req, cacheBuster);
        }

        messageInfo.setRequest(req);
    }

    private void launchScan(IHttpRequestResponse messageInfo) {
        if (!BulkUtilities.globalSettings.getBoolean("enable auto-mine")) {
            return;
        }

        IRequestInfo reqInfo = BulkUtilities.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        if (!BulkUtilities.callbacks.isInScope(reqInfo.getUrl())) {
            return;
        }

        IResponseInfo respInfo = BulkUtilities.helpers.analyzeResponse(messageInfo.getResponse());
        StringBuilder codeBuidler = new StringBuilder();
        String contentType = respInfo.getStatedMimeType();

        codeBuidler.append(reqInfo.getUrl().getHost());
        codeBuidler.append(contentType);

        String broadCode = codeBuidler.toString();
        if (!alreadyScanned.contains(broadCode)){
            //BulkUtilities.out("Queueing headers+cookies on "+reqInfo.getUrl());
            if (BulkUtilities.globalSettings.getBoolean("auto-mine headers")) {
                taskEngine.execute(new ParamGuesser(BulkUtilities.callbacks.saveBuffersToTempFiles(messageInfo), false, BulkUtilities.PARAM_HEADER, this, taskEngine, BulkUtilities.globalSettings.getInt("rotation interval"), BulkUtilities.globalSettings));
            }
            if (BulkUtilities.globalSettings.getBoolean("auto-mine cookies")) {
                taskEngine.execute(new ParamGuesser(BulkUtilities.callbacks.saveBuffersToTempFiles(messageInfo), false, IParameter.PARAM_COOKIE, this, taskEngine, BulkUtilities.globalSettings.getInt("rotation interval"), BulkUtilities.globalSettings));
            }

            alreadyScanned.add(broadCode);
        }

        if (!BulkUtilities.globalSettings.getBoolean("auto-mine params")) {
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

        BulkUtilities.out("Queueing params on "+reqInfo.getUrl());
        taskEngine.execute(new ParamGuesser(BulkUtilities.callbacks.saveBuffersToTempFiles(messageInfo), false, guessType, this, taskEngine, BulkUtilities.globalSettings.getInt("rotation interval"), BulkUtilities.globalSettings));
        alreadyScanned.add(paramCode);
    }
}
