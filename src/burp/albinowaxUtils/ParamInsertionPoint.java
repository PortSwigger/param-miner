//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.IParameter;
import burp.IScannerInsertionPoint;

public class ParamInsertionPoint implements IScannerInsertionPoint {
public byte[] request;
String name;
public String value;
public byte   type;
public burp.Utilities utilities;

public ParamInsertionPoint(byte[] request, IParameter param, burp.Utilities utilities) {
  this.request = request;
  this.name = param.getName();
  this.value = param.getValue();
  this.type = param.getType();
  this.utilities = utilities;
}

public ParamInsertionPoint(byte[] request, String name, String value, byte type, burp.Utilities utilities) {
  this.request = request;
  this.name = name;
  this.value = value;
  this.type = type;
  this.utilities = utilities;
}

public String calculateValue(String unparsed) {
  return unparsed;
}

public String getInsertionPointName() {
  return this.name;
}

public String getBaseValue() {
  return this.value;
}

public byte[] buildRequest(byte[] payload) {
  IParameter newParam = utilities.helpers.buildParameter(this.name, utilities.encodeParam(utilities.helpers.bytesToString(payload)), this.type);
  return utilities.helpers.updateParameter(this.request, newParam);
}

public int[] getPayloadOffsets(byte[] payload) {
  return new int[]{0, 0};
}

public byte getInsertionPointType() {
  return this.type;
}
}
