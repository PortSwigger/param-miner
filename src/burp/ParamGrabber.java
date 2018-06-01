package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.omg.PortableInterceptor.RequestInfo;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;

public class ParamGrabber implements IHttpListener  {

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
        if (messageIsRequest) {
            addCacheBusters(messageInfo);
        }
        else {
            saveParams(messageInfo);
            if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
                launchScan(messageInfo);
            }
        }
    }

    Set<String> getSavedWords() {
        return savedWords;
    }

    void saveParams(IHttpRequestResponse baseRequestResponse) {
        // todo also use observed requests
        String body = Utilities.getBody(baseRequestResponse.getResponse());
        if (!body.equals("")) {
            savedWords.addAll(getWords(Utilities.helpers.bytesToString(baseRequestResponse.getResponse())));
            savedGET.addAll(getHtmlKeys(body));
            try {
                JsonParser parser = new JsonParser();
                JsonElement json = parser.parse(body);
                ArrayList<String> keys = Keysmith.getJsonKeys(json, new HashMap<>());
                if (!done.contains(keys)) {
                    //Utilities.out("Importing observed data...");
                    done.add(keys);
                    savedJson.add(Utilities.callbacks.saveBuffersToTempFiles(baseRequestResponse));
                }
            } catch (JsonParseException e) {

            }
        }
    }

    private void addCacheBusters(IHttpRequestResponse messageInfo) {
        byte[] placeHolder = Utilities.helpers.stringToBytes("$randomplz");
        if (Utilities.countMatches(messageInfo.getRequest(), placeHolder) > 0) {
            messageInfo.setRequest(
                    Utilities.fixContentLength(Utilities.replace(messageInfo.getRequest(), placeHolder, Utilities.helpers.stringToBytes(Utilities.generateCanary())))
            );
        }

        String cacheBusterName = null;
        if (Utilities.globalSettings.getBoolean("Add dynamic cachebuster")) {
            cacheBusterName = Utilities.generateCanary();
        }
        else if (Utilities.globalSettings.getBoolean("Add fixed cachebuster")) {
            cacheBusterName = "fcbz";
        }

        if (cacheBusterName != null) {
            IParameter cacheBuster = burp.Utilities.helpers.buildParameter(cacheBusterName, "1", IParameter.PARAM_URL);
            messageInfo.setRequest(Utilities.helpers.addParameter(messageInfo.getRequest(), cacheBuster));
        }
    }

    private void launchScan(IHttpRequestResponse messageInfo) {
        if (!Utilities.globalSettings.getBoolean("auto-mine proxy traffic")) {
            return;
        }

        IRequestInfo reqInfo = Utilities.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
        if (!Utilities.callbacks.isInScope(reqInfo.getUrl())) {
            return;
        }

        IResponseInfo respInfo = Utilities.helpers.analyzeResponse(messageInfo.getResponse());
        StringBuilder codeBuidler = new StringBuilder();
        String contentType = respInfo.getStatedMimeType();

        codeBuidler.append(reqInfo.getUrl().getHost());
        codeBuidler.append(contentType);

        String broadCode = codeBuidler.toString();
        if (!alreadyScanned.contains(broadCode)){
            taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, IParameter.PARAM_COOKIE, this, taskEngine, Utilities.globalSettings.getInt("rotation interval"), Utilities.globalSettings));
            taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, Utilities.PARAM_HEADER, this, taskEngine, Utilities.globalSettings.getInt("rotation interval"), Utilities.globalSettings));
            alreadyScanned.add(broadCode);
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

        taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(messageInfo), false, IParameter.PARAM_URL, this, taskEngine, Utilities.globalSettings.getInt("rotation interval"), Utilities.globalSettings));
        alreadyScanned.add(paramCode);

    }
}
