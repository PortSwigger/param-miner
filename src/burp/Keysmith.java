package burp;

import com.google.gson.*;

import java.util.*;

/**
 * Created by james on 06/09/2017.
 */
public class Keysmith {

    static ArrayList<String> getJsonKeys(JsonElement json, HashMap<String, String> witnessedParams){
        try {
            return getJsonKeys(json, null, witnessedParams);
        }
        catch (JsonParseException e) {
            return new ArrayList<>();
        }

    }

    static ArrayList<String> getAllKeys(byte[] resp, HashMap<String, String> witnessedParams){
        try {
            return getJsonKeys(new JsonParser().parse(Utilities.getBody(resp)), witnessedParams);
        }
        catch (JsonParseException e) {
            return new ArrayList<>();
        }
    }

    private static ArrayList<String> getParamKeys(byte[] resp, HashMap<String, String> witnessedParams) {
        ArrayList<String> keys = new ArrayList<>();
        IRequestInfo info = Utilities.helpers.analyzeRequest(resp);
        List<IParameter> currentParams = info.getParameters();

        for (IParameter param : currentParams) {
            keys.add(param.getName());
        }
        return keys;
    }

    // fixme still returns keys starting with ':' sometimes
    private static ArrayList<String> getJsonKeys(JsonElement json, String prefix, HashMap<String, String> witnessedParams) {
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
                keys.addAll(getJsonKeys(entry.getValue(), tempPrefix, witnessedParams));
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
                keys.addAll(getJsonKeys(x, tempPrefix, witnessedParams));
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
