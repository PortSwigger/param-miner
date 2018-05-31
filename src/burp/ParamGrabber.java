package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;

public class ParamGrabber implements IHttpListener  {

    Set<IHttpRequestResponse> getSavedJson() {
        return savedJson;
    }
    private Set<IHttpRequestResponse> savedJson;
    private HashSet<ArrayList<String>> done;
    Set<String> getSavedGET() {
        return savedGET;
    }
    private Set<String> savedGET;
    private Set<String> savedWords;

    ParamGrabber() {
        savedJson = ConcurrentHashMap.newKeySet();
        //savedJson = ConcurrentHashMap.newKeySet();//new HashSet<>();
        done = new HashSet<>();
        savedWords = ConcurrentHashMap.newKeySet();
        savedGET = ConcurrentHashMap.newKeySet();
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && Utilities.globalSettings.getBoolean("autoscan")) {
                launchScan(messageInfo);
            }

            addCacheBusters(messageInfo);
        }
        else {
            saveParams(messageInfo);
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
        // todo scan this request if we haven't already seen it
    }
}
