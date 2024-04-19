package burp;

import burp.model.utilities.Utilities;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public static ArrayList<String> getAllKeys(
      byte[] resp, HashMap<String, String> witnessedParams, Utilities utilities
    ){
        if (!"".equals(Utilities.getBody(resp))) {
            try {
                return getJsonKeys(new JsonParser().parse(Utilities.getBody(resp)), witnessedParams);
            }
            catch (JsonParseException e) {

            }
        }

        if(Utilities.isResponse(resp)) {
            return getHtmlKeys(Utilities.getBody(resp));
        }
        else {
            return getParamKeys(resp, new HashSet<>(), utilities);
        }

    }

    static ArrayList<String> getParamKeys(byte[] resp, HashSet<Byte> types, Utilities utilities) {
        ArrayList<String> keys = new ArrayList<>();

        List<IParameter> currentParams = utilities.helpers.analyzeRequest(resp).getParameters();

        for (IParameter param : currentParams) {
            String parsedParam = parseParam(param.getName().replace(':', ';'));
            if(types.isEmpty() || types.contains(param.getType())) {
                keys.add(parsedParam);
                utilities.log(parsedParam);
            }
        }
        return keys;
    }

    static String parseParam(String param) {
        param = param.replace("%5B", "[").replace("%5D", "]");
        StringBuilder parsed = new StringBuilder();
        for (String e: param.split("\\[")) {
            parsed.append(":");
            parsed.append(e.replace("]", ""));
        }

        if (parsed.length() == 0) {
            return "";
        }

        return parsed.toString().substring(1);
    }

    public static String unparseParam(String param) {
        String[] presplit = param.split("~", 2);
        StringBuilder unparsed = new StringBuilder();
        String[] split = presplit[0].split(":", -1);
        unparsed.append(split[0]);
        for (int i=1;i<split.length;i++) {
            unparsed.append("[");
            unparsed.append(split[i]);
            unparsed.append("]");
        }
        String output = unparsed.toString();
        if (presplit.length > 1) {
            output = output + "~" + presplit[1];
        }

        return output;
    }

    static HashSet<String> getWords(String body) {
        HashSet<String> longWords = new HashSet<>(Arrays.asList(body.split("[^.a-zA-Z0-9_-]")));
        longWords.addAll(Arrays.asList(body.split("[^a-zA-Z0-9]")));
        return longWords;
    }


    static ArrayList<String> getHtmlKeys(String body) {
        HashSet<String> params = new HashSet<>();
        Document doc = Jsoup.parse(body);
        Elements links = doc.select("a[href]");
        for(Element link: links) {
            String url = link.attr("href");
            if(url.contains("?")) {
                url = url.split("[?]", 2)[1];
                String[] chunks = url.split("&");
                for (String chunk: chunks) {
                    String[] keyvalue = chunk.split("=", 2);
                    String key = keyvalue[0];
                    if (keyvalue.length > 1 && Utilities.invertable(keyvalue[1])) {
                        key = key + "~" + keyvalue[1];
                    }
                    params.add(key);
                    //Utilities.out("HTML PARAM: "+chunk.split("=", 2)[0]);
                }
            }
        }
        Elements inputs = doc.select("input[name]");
        for(Element input: inputs) {
            String key= input.attr("name");
            if (Utilities.invertable(input.attr("value"))) {
                key = key + "~" + input.attr("value");
            }
            params.add(key);
        }

        Elements scripts = doc.select("script");
        for(Element script: scripts) {
            String content = script.html();
            Matcher matched = Pattern.compile("\"([a-zA-Z0-9_]+)\":").matcher(content);
            while(matched.find()) {
                params.add(matched.group(1));
            }
        }

        return new ArrayList<String>(params);
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
            if (prefix != null) {

                try {
                    if (!json.getAsJsonPrimitive().isJsonNull()) {
                        String val = json.getAsString();
                        if (Utilities.invertable(val)) {
                            prefix = prefix + "~" + val;
                        }
                    }
                } catch (java.lang.IllegalStateException e) {

                }


                keys.add(prefix); // todo append value here
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

    static String getKey(String param) {
        String[] keys = param.split(":");
        for (int i=keys.length-1; i>=0; i--) {
            if (Utilities.parseArrayIndex(keys[i]) == -1) {
                return keys[i];
            }
        }
        return param;
    }

    static String permute(String fullparam) {
        return permute(fullparam, false);
    }

    static String permute(String fullparam, boolean allowValueChange) {
        String[] params = fullparam.split("[|]");
        ArrayList<String> out = new ArrayList<>();
        for (String eachparam: params) {
            if (allowValueChange && eachparam.contains("~") && !eachparam.contains("%")) {
                String[] param = eachparam.split("~", 2);
                out.add(param[0] + "~" + Utilities.invert(param[1]));
            } else {
                String[] keys = eachparam.split(":");
                String[] param = null;
                if (eachparam.contains("~")) {
                    param = eachparam.split("~", 2);
                    keys = param[0].split(":");
                }
                for (int i = keys.length - 1; i >= 0; i--) {
                    if (Utilities.parseArrayIndex(keys[i]) == -1) {
                        keys[i] += Utilities.randomString(6);
                        break;
                    }
                }

                String tempOut = String.join(":", keys);
                if (eachparam.contains("~")) {
                    tempOut += "~" + param[1];
                }
                out.add(tempOut);
            }
        }

        return String.join("|", out);

    }

}
