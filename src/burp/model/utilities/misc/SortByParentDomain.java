//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.model.utilities.misc;

import java.util.Comparator;

import burp.model.scanning.ScanItem;
import org.apache.commons.lang3.StringUtils;

public class SortByParentDomain implements Comparator<ScanItem> {

@Override
public int compare(ScanItem o1, ScanItem o2) {
  int dot1 = StringUtils.countMatches(o1.host, ".");
  int dot2 = StringUtils.countMatches(o2.host, ".");
  int score = dot1 - dot2;
  if (score == 0) {
    score = o1.host.length() - o2.host.length();
  }
  
  if (score == 0) {
    score = o1.hashCode() - o2.hashCode();
  }
  
  if (score == 0) {
    String path1 = Utilities.getPathFromRequest(o1.req.getRequest());
    String path2 = Utilities.getPathFromRequest(o2.req.getRequest());
    score = path2.length() - path1.length();
  }
  
  return score;
}
}
