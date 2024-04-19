package burp.model.scanning;

import burp.IExtensionStateListener;
import burp.Utilities;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ScanPool extends ThreadPoolExecutor implements IExtensionStateListener {
public AtomicInteger candidates = new AtomicInteger(0);
AtomicInteger findings = new AtomicInteger(0);

ScanPool(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue,
         Utilities utilities
) {
  super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
  utilities.callbacks.registerExtensionStateListener(this);
}

public void extensionUnloaded() {
  this.getQueue().clear();
  this.shutdown();
}
}