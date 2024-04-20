package burp.model.insertionPoints;

import burp.model.utilities.misc.Utilities;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class JsonParamNameInsertionPoint extends ParamInsertionPoint {
final byte[] headers;
final byte[] body;
final String baseInput;
final String attackID;
final JsonElement root;

public JsonParamNameInsertionPoint(
  byte[] request, String name, String value, byte type, String attackID, Utilities utilities
) {
  super(request, name, value, type, utilities); // utilities.encodeJSON(value)
  int start = Utilities.getBodyStart(request);
  this.attackID = attackID;
  headers = Arrays.copyOfRange(request, 0, start);
  body = Arrays.copyOfRange(request, start, request.length);
  baseInput = utilities.helpers.bytesToString(body);
  root = new JsonParser().parse(baseInput);
}

private Object makeNode(ArrayList<String> keys, int i, Object paramValue) {
  if (i+1 == keys.size()) {
    return paramValue;
  }
  else if (Utilities.parseArrayIndex(keys.get(i+1)) != -1) {
    return new ArrayList(Utilities.parseArrayIndex(keys.get(i+1)));
  }
  else {
    return new HashMap();
  }
}

public String calculateValue(String unparsed) {
  return utilities.toCanary(unparsed) + attackID + value + utilities.fuzzSuffix();
}


@Override
@SuppressWarnings("unchecked")
public byte[] buildRequest(byte[] payload) throws RuntimeException {
  String[] params = utilities.helpers.bytesToString(payload).split("[|]");
  String lastBuild = baseInput;
  
  try {
    for (String unparsed: params) {
      
      Object paramValue;
      if (unparsed.contains("~")) {
        String[] parts = unparsed.split("~", 2);
        unparsed = parts[0];
        paramValue = Utilities.invert(parts[1]);
      } else {
        paramValue = calculateValue(unparsed);
      }
      
      ArrayList<String> keys = new ArrayList<>(Arrays.asList(unparsed.split(":")));
      
      boolean isArray = Utilities.parseArrayIndex(keys.get(0)) != -1;
      Object base;
      if (isArray) {
        try {
          base = new ObjectMapper().readValue(lastBuild, ArrayList.class);
        }
        catch (MismatchedInputException e) {
          base = new ArrayList();
        }
      } else {
        try {
          base = new ObjectMapper().readValue(lastBuild, HashMap.class);
        }
        catch (MismatchedInputException e) {
          base = new HashMap();
        }
      }
      
      Object next = base;
      for (int i = 0; i < keys.size(); i++) {
        
        try {
          String key = keys.get(i);
          boolean setValue = i + 1 == keys.size();
          
          int index = Utilities.parseArrayIndex(key);
          if (index != -1) {
            ArrayList injectionPoint = (ArrayList) next;
            if (injectionPoint.size() < index + 1) {
              for (int k = injectionPoint.size(); k < index; k++) {
                injectionPoint.add(Utilities.generateCanary());
              }
              injectionPoint.add(makeNode(keys, i, paramValue));
            } else if (injectionPoint.get(index) == null || setValue) {
              injectionPoint.set(index, makeNode(keys, i, paramValue));
            }
            next = injectionPoint.get(index);
          } else {
            HashMap injectionPoint = (HashMap) next;
            if (!injectionPoint.containsKey(key) || setValue) {
              injectionPoint.put(key, makeNode(keys, i, paramValue));
            }
            next = injectionPoint.get(key);
          }
        } catch(ClassCastException e) {
          //utilities.out("Cast error"); // todo figure out a sensible action to stop this form occuring
        }
      }
      
      lastBuild = new ObjectMapper().writeValueAsString(base);
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(headers);
    outputStream.write(utilities.helpers.stringToBytes(lastBuild));
    return Utilities.fixContentLength(outputStream.toByteArray());
  } catch (Exception e) {
    utilities.out("Error with " + String.join(":", params));
    e.printStackTrace(new PrintStream(utilities.callbacks.getStdout()));
    return buildRequest(utilities.helpers.stringToBytes("error_" + String.join(":", params).replace(":", "_")));
    // throw new RuntimeException("Request creation unexpectedly failed: "+e.getMessage());
  }
}
}
