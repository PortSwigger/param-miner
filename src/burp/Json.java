package burp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by james on 06/09/2017.
 */
public class Json {

    static ArrayList<String> getAllKeys(JsonElement json, HashMap<String, String> witnessedParams){
        try {
            return getAllKeys(json, null, witnessedParams);
        }
        catch (JsonParseException e) {
            return new ArrayList<>();
        }
    }

    static ArrayList<String> getAllKeys(byte[] resp, HashMap<String, String> witnessedParams){
        return getAllKeys(new JsonParser().parse(Utilities.getBody(resp)), witnessedParams);
    }

    // fixme still returns keys starting with ':' sometimes
    private static ArrayList<String> getAllKeys(JsonElement json, String prefix, HashMap<String, String> witnessedParams) {
        ArrayList<String> keys = new ArrayList<>();

        if (json.isJsonObject()) {
            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                if (witnessedParams.containsKey(entry.getKey())) {
                    //Utilities.out("Recognised '"+entry.getKey()+", replacing prefix '"+prefix+"' with '"+ witnessedParams.get(entry.getKey())+"'");
                    if(witnessedParams.get(entry.getKey()).equals("")) {
                        prefix = null;
                    }
                    else {
                        prefix = witnessedParams.get(entry.getKey());
                    }
                    break;
                }
            }

            for (Map.Entry<String,JsonElement> entry: json.getAsJsonObject().entrySet()) {
                String tempPrefix = entry.getKey();
                if (prefix != null) {
                    tempPrefix = prefix+":"+tempPrefix;
                }
                keys.addAll(getAllKeys(entry.getValue(), tempPrefix, witnessedParams));
            }

            if(prefix != null) {
                keys.add(prefix);
            }

        } else if (json.isJsonArray()) {
            JsonArray hm = json.getAsJsonArray();
            int i = 0;
            for (JsonElement x: hm) {
                String tempPrefix = "[" + Integer.toString(i++)+"]";
                if (prefix != null) {
                    tempPrefix = prefix+":"+tempPrefix;
                }
                keys.addAll(getAllKeys(x, tempPrefix, witnessedParams));
            }
        }


        else {
            //if (prefix.startsWith(":")) {
            //    prefix = prefix.substring(1);
            //}
            // Utilities.out(prefix);
            if (prefix != null) {
                keys.add(prefix);
            }
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

}
