//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.model.scanning;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.controller.TriggerBulkScan;
import burp.model.utilities.Utilities;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

class OfferBulkScan implements IContextMenuFactory {
private       List<Scan>       scans;
private final Utilities        utilities;
private final BulkScanLauncher launcher;

OfferBulkScan(List<Scan> scans, Utilities utilities, BulkScanLauncher launcher) {
  this.scans     = scans;
  this.utilities = utilities;
  this.launcher  = launcher;
}

public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
  IHttpRequestResponse[] reqs    = invocation.getSelectedMessages();
  List<JMenuItem>        options = new ArrayList();
  JMenu scanMenu = new JMenu(utilities.name);
  Iterator var5;
  Scan scan;
  JMenuItem probeButton;
  if (reqs != null && reqs.length > 0) {
    var5 = this.scans.iterator();
    
    while(var5.hasNext()) {
      scan = (Scan)var5.next();
      probeButton = new JMenuItem(scan.name);
      probeButton.addActionListener(new TriggerBulkScan(scan, reqs, utilities, launcher));
      scanMenu.add(probeButton);
    }
  } else if (invocation.getSelectedIssues().length > 0) {
    var5 = this.scans.iterator();
    
    while(var5.hasNext()) {
      scan = (Scan)var5.next();
      probeButton = new JMenuItem(scan.name);
      probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues(), utilities, launcher));
      scanMenu.add(probeButton);
    }
  }
  
  options.add(scanMenu);
  return options;
}
}
