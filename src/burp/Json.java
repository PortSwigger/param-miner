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


    static String[] parseKey(String entry) {
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
        String[] parsed = new String[2];
        parsed[0] = prefix;
        parsed[1] = key;
        return parsed;
    }




    static ArrayList<String> getLinkedParams(String body, ArrayList<String> rawRequestParams, HashSet<String> witnessedParams) {
        ArrayList<String> found = new ArrayList<>();
        try {
            JsonParser parser = new JsonParser();
            HashMap<String, String> requestParams = new HashMap<>();

            // todo give precedence to shallower keys
            for (String entry: rawRequestParams) {
                String[] parsed = parseKey(entry);
                requestParams.putIfAbsent(parsed[1], parsed[0]);
                witnessedParams.add(parsed[1]);
                witnessedParams.add(parsed[0]);
            }

            found = getAllKeys(parser.parse(body), "", requestParams);
        }
        catch (Exception e) {

        }

        return found;
    }
}
