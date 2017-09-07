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

    /*static ArrayList<String> justGetKeys(String json) {
        JsonParser parser = new JsonParser();
        parser.parse(json);
        return getAllKeys(parser.parse(json), "", new HashMap<>());
    }

    static ArrayList<String> remapKeys(ArrayList<String> keys, ArrayList<String> rawRequestParams) {
        HashMap<String, String> requestParams = new HashMap<>();

        // todo give precedence to shallower keys
        for (String entry: rawRequestParams) {
            String[] parsed = parseKey(entry);
            for (String key: keys) {
        //        key.replace(parsed)
            }
            requestParams.putIfAbsent(parsed[1], parsed[0]);
        }


        for (String key: keys) {

        }
    }*/

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




    static ArrayList<String> getLinkedParams(JsonElement json, HashMap<String, String> requestParams) {
        ArrayList<String> found = new ArrayList<>();
        try {
            found = getAllKeys(json, "", requestParams);
        }
        catch (Exception e) {

        }

        return found;
    }
}
