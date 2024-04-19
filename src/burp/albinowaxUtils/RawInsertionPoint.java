//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.IScannerInsertionPoint;
import burp.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class RawInsertionPoint implements IScannerInsertionPoint {
private byte[] prefix;
private byte[] suffix;
private String baseValue;
private String name;

public RawInsertionPoint(byte[] req, String name, int start, int end) {
  this.name = name;
  this.prefix = Arrays.copyOfRange(req, 0, start);
  this.suffix = Arrays.copyOfRange(req, end, req.length);
  this.baseValue = new String(Arrays.copyOfRange(req, start, end));
}

public String getInsertionPointName() {
  return this.name;
}

public String getBaseValue() {
  return this.baseValue;
}

public byte[] buildRequest(byte[] payload) {
  ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
  
  try {
    outputStream.write(this.prefix);
    outputStream.write(payload);
    outputStream.write(this.suffix);
  } catch (IOException var4) {
  }
  
  return Utilities.fixContentLength(outputStream.toByteArray());
}

public int[] getPayloadOffsets(byte[] payload) {
  return new int[]{this.prefix.length, this.prefix.length + payload.length};
}

public byte getInsertionPointType() {
  return 65;
}
}
