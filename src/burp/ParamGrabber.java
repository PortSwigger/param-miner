package burp;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static burp.Keysmith.getHtmlKeys;
import static burp.Keysmith.getWords;

class ParamGrabber implements IScannerCheck {

    public Set<IHttpRequestResponse> getSavedJson() {
        return savedJson;
    }

    Set<IHttpRequestResponse> savedJson;
    HashSet<ArrayList<String>> done;

    public Set<String> getSavedGET() {
        return savedGET;
    }

    Set<String> savedGET;

    public Set<String> getSavedWords() {
        return savedWords;
    }

    Set<String> savedWords;

    ParamGrabber() {
        savedJson = ConcurrentHashMap.newKeySet();
        //savedJson = ConcurrentHashMap.newKeySet();//new HashSet<>();
        done = new HashSet<>();
        savedWords = ConcurrentHashMap.newKeySet();
        savedGET = ConcurrentHashMap.newKeySet();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (Utilities.globalSettings.getBoolean("learn observed words")) {
            saveParams(baseRequestResponse);
        }
        return new ArrayList<>();
    }

    public void saveParams(IHttpRequestResponse baseRequestResponse) {
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

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }
}