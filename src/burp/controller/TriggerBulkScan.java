//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.controller;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.model.scanning.BulkScan;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.Scan;
import burp.model.utilities.misc.Utilities;
import burp.view.ConfigurableSettings;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class TriggerBulkScan implements ActionListener {
private IHttpRequestResponse[] reqs;
private       IScanIssue[]     issues;
private       Scan             scan;
private final Utilities        utilities;
private final BulkScanLauncher luancher;

public TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs, Utilities utilities, BulkScanLauncher luancher) {
  this.scan = scan;
  this.reqs = reqs;
  this.utilities = utilities;
  this.luancher = luancher;
}

public TriggerBulkScan(Scan scan, IScanIssue[] issues, Utilities utilities, BulkScanLauncher luancher) {
  this.scan = scan;
  this.issues = issues;
  this.utilities = utilities;
  this.luancher = luancher;
}

public void actionPerformed(ActionEvent e) {
  if (this.reqs == null) {
    this.reqs = new IHttpRequestResponse[this.issues.length];
    
    for(int i = 0; i < this.issues.length; ++i) {
      IScanIssue issue = this.issues[i];
      this.reqs[i] = issue.getHttpMessages()[0];
    }
  }
  
  ConfigurableSettings config = utilities.globalSettings.showSettings(this.scan.scanSettings.getSettings());
  if (config != null) {
    BulkScan bulkScan = new BulkScan(this.scan, this.reqs, config, utilities, luancher);
    (new Thread(bulkScan)).start();
  }
  
}

}
