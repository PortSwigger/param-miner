package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by james on 06/09/2017.
 */
public class Json {

    static ArrayList<String> getAllKeys(JsonElement json, String prefix, HashMap<String, String> witnessedParams) {
        ArrayList<String> keys = new ArrayList<>();

        if (json.isJsonObject()) {
            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                if (witnessedParams.containsKey(entry.getKey())) {
                    Utilities.out("Recognised '"+entry.getKey()+"', replacing prefix '"+prefix+"' with '"+ witnessedParams.get(entry.getKey())+"'");
                    prefix = witnessedParams.get(entry.getKey());
                    break;
                }
            }

            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                keys.addAll(getAllKeys(entry.getValue(), prefix + ":" + entry.getKey(), witnessedParams));
            }

            keys.add(prefix);

        } else if (json.isJsonArray()) {
            JsonArray hm = json.getAsJsonArray();
            int i = 0;
            for (JsonElement x: hm) {
                keys.addAll(getAllKeys(x, prefix + ":[" + Integer.toString(i++)+"]", witnessedParams));
            }
        }


        else {
            if (prefix.startsWith(":")) {
                prefix = prefix.substring(1);
            }
            // Utilities.out(prefix);
            keys.add(prefix);
        }


        return keys;
    }

    static ArrayList<String> getParamsFromResponse(IHttpRequestResponse baseRequestResponse, HashSet<String> witnessedParams) {
        if (baseRequestResponse.getResponse() == null) {
            Utilities.out("No baserequest has no response - fetching...");
            baseRequestResponse = Utilities.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
        }
        String body = Utilities.getBody(baseRequestResponse.getResponse());


        ArrayList<String> found = new ArrayList<>();
        try {
            JsonParser parser = new JsonParser();
            HashMap<String, String> requestParams = new HashMap<>();

            // todo give precedence to shallower keys
            ArrayList<String> rawRequestParams = getAllKeys(parser.parse(Utilities.getBody(baseRequestResponse.getRequest())), "", new HashMap<String, String>());
            for (String entry: rawRequestParams) {
                int keyStart = entry.lastIndexOf(':');
                String prefix;
                String key;
                if (keyStart != -1) {
                    prefix = entry.substring(0, keyStart);
                    key = entry.substring(keyStart + 1);
                }
                else {
                    prefix = "";
                    key = entry;
                }
                requestParams.putIfAbsent(key, prefix);
                witnessedParams.add(key);
                witnessedParams.add(prefix);
            }

            found = getAllKeys(parser.parse(body), "", requestParams);
        }
        catch (Exception e) {

        }

        return found;
    }
}
