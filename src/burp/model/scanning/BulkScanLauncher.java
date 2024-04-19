package burp.model.scanning;


import burp.model.utilities.Utilities;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class BulkScanLauncher {
private       ScanPool  taskEngine;
private final Utilities utilities;

public BulkScanLauncher(List<Scan> scans, Utilities utilities) {
  this.utilities = utilities;
  taskEngine     = buildTaskEngine();
  utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scans, utilities, this));
}

private ScanPool buildTaskEngine() {
  BlockingQueue<Runnable> tasks = new LinkedBlockingQueue();
  utilities.globalSettings.registerSetting("thread pool size", 8, "The maximum number of threads this tool will spin up. This roughly correlates with the number of concurrent requests. Increasing this value will make attacks run faster, and use more computer resources.");
  ScanPool taskEngine = new ScanPool(utilities.globalSettings.getInt("thread pool size"), utilities.globalSettings.getInt("thread pool size"), 10L, TimeUnit.MINUTES, tasks, utilities);
  utilities.globalSettings.registerListener("thread pool size", (value) -> {
    utilities.out("Updating active thread pool size to " + value);
    
    try {
      taskEngine.setCorePoolSize(Integer.parseInt(value));
      taskEngine.setMaximumPoolSize(Integer.parseInt(value));
    } catch (IllegalArgumentException var3) {
      taskEngine.setMaximumPoolSize(Integer.parseInt(value));
      taskEngine.setCorePoolSize(Integer.parseInt(value));
    }
    
  });
  return taskEngine;
}

public ScanPool getTaskEngine() {
  return taskEngine;
}
}
