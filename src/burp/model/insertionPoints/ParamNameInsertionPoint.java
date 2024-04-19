package burp.model.insertionPoints;

import burp.IParameter;
import burp.Keysmith;
import burp.model.utilities.Utilities;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParamNameInsertionPoint extends ParamInsertionPoint {
    String                  attackID;
    String                  defaultPrefix;
    String                  host;
    HashMap<String, String> present;

    public ParamNameInsertionPoint(
      byte[] request, String name, String value, byte type, String attackID, Utilities utilities
    ) {
        super(request, name, value, type, utilities);
        this.attackID = attackID;
    
        ArrayList<String>        keys = Keysmith.getAllKeys(request, new HashMap<>(), utilities);
        HashMap<String, Integer> freq = new HashMap<>();
        for (String key: keys) {
            if (key.contains(":")) {
                String object = key.split(":")[0];
                freq.put(object, freq.getOrDefault(object, 0) + 1);
            }
        }

        String maxKey = null;

        if (utilities.globalSettings.getBoolean("auto-nest params")) {
            int max = 0;
            for (Map.Entry<String, Integer> entry : freq.entrySet()) {
                if (entry.getValue() > max) {
                    maxKey = entry.getKey();
                    max = entry.getValue();
                }
            }
        }
        defaultPrefix = maxKey;

        if (maxKey != null) {
            utilities.out("Selected default key: "+maxKey);
        }
        else {
            utilities.log("No default key available");
        }

        present = new HashMap<>();
        List<String> headers = utilities.analyzeRequest(request).getHeaders();
        for (String header: headers) {
            if (header.startsWith("Host: ")) {
                host = header.split(": ", 2)[1];
            }
            header = header.split(": ", 2)[0];
            if (utilities.globalSettings.getBoolean("lowercase headers")) {
                present.put(header.toLowerCase(), header);
            }
            else {
                present.put(header, header);
            }
        }
    }

    public String calculateValue(String unparsed) {
        String canary = utilities.globalSettings.getString("force canary");
        if (!"".equals(canary)) {
            return canary;
        }
        return utilities.toCanary(unparsed) + attackID + value + utilities.fuzzSuffix();
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        String bulk = utilities.helpers.bytesToString(payload);
        String[] params = bulk.split("[|]");
        ArrayList<String> preppedParams = new ArrayList<>();
        for(String key: params) {
            if (defaultPrefix != null && !key.contains(":")) {
                key = defaultPrefix + ":" + key;
            }
            preppedParams.add(Keysmith.unparseParam(key));
        }

        if(type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_COOKIE || type == Utilities.PARAM_HEADER) {
            return buildBulkRequest(preppedParams);
        }

        return buildBasicRequest(preppedParams);
    }

    public byte[] buildBulkRequest(ArrayList<String> params) {
        String merged = prepBulkParams(params);
        String replaceKey = "TCZqBcS13SA8QRCpW";
        IParameter newParam = utilities.helpers.buildParameter(replaceKey, "", type);
        byte[] built = utilities.helpers.updateParameter(request, newParam);
        return utilities.fixContentLength(utilities.replace(built, utilities.helpers.stringToBytes(replaceKey+"="), utilities.helpers.stringToBytes(merged)));
    }

    String prepBulkParams(ArrayList<String> params) {
        ArrayList<String> preppedParams = new ArrayList<>();

        String equals;
        String join;
        String trail;
        if(type == IParameter.PARAM_COOKIE) {
            equals = "=";
            join = "; ";
            trail = ";";
        }
        else if (type == Utilities.PARAM_HEADER) {
            equals = ": ";
            join ="\r\n";
            trail = ""; // \r\n
        }
        else {
            equals = "=";
            join = "&";
            trail = "";
        }


        for (String param: params) {
            String fullParam[] = getValue(param);
            if ("".equals(fullParam[0])) {
                continue;
            }
            if (type == Utilities.PARAM_HEADER) {
                preppedParams.add(fullParam[0] + equals + fullParam[1]);
            }
            else {
                preppedParams.add(utilities.encodeParam(fullParam[0]) + equals + utilities.encodeParam(fullParam[1]));
            }
        }

        return String.join(join, preppedParams) + trail;
    }

    String[] getValue(String name) {
        if (name.contains("~")) {
            String[] parts = name.split("~", 2);
            parts[1] = parts[1].replace("%s", calculateValue(name));
            parts[1] = parts[1].replace("%h", host);
            return new String[]{parts[0], String.valueOf(utilities.invert(parts[1]))};
        }
        else {
            return new String[]{name, calculateValue(name)};
        }
    }

    byte[] buildBasicRequest(ArrayList<String> params) {
        byte[] built = request;
        for (String name: params) {
            String[] param = getValue(name);
            IParameter newParam = utilities.helpers.buildParameter(param[0], utilities.encodeParam(param[1]), type);
            built = utilities.helpers.updateParameter(built, newParam);
        }
        return built;
    }
}
