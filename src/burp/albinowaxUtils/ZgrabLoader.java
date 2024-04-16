//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.IHttpService;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class ZgrabLoader {
private Connection conn;
private Scan scanner;

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
