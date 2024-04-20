//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.model.utilities.misc;

import burp.model.scanning.Scan;

import java.sql.Connection;
import java.sql.DriverManager;

public class ZgrabLoader {
private Connection conn;
private Scan       scanner;

ZgrabLoader(Scan scanner) {
  this.scanner = scanner;
  
  try {
    Class.forName("org.sqlite.JDBC");
    this.conn = DriverManager.getConnection("jdbc:sqlite:/Users/james/PycharmProjects/zscanpipeline/requests.db");
  } catch (Exception var3) {
    Exception e = var3;
    e.printStackTrace();
  }
  
}
}
