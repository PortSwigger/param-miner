package burp.model.scanning;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.model.utilities.Utilities;
import burp.model.utilities.SortByParentDomain;
import burp.view.ConfigurableSettings;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.lang3.math.NumberUtils;

public class BulkScan implements Runnable {
private       IHttpRequestResponse[]    reqs;
private       Scan                 scan;
private       ConfigurableSettings config;
public static List<Scan>           scans = new ArrayList();
public static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap();

public BulkScan(
  Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config, Utilities utilities,
  BulkScanLauncher luancher
) {
  this.scan = scan;
  this.reqs = reqs;
  this.config = config;
  this.utilities = utilities;
  this.luancher = luancher;
}

static boolean domainAlreadyFlagged(IHttpService service, Utilities utilities) {
  if (domainAlreadyFlaggedInThisScan(service)) {
    return true;
  } else if (utilities.callbacks.getScanIssues(service.getProtocol() + "://" + service.getHost()).length > 0) {
    hostsToSkip.put(service.getHost(), true);
    return true;
  } else {
    return false;
  }
}

static boolean domainAlreadyFlaggedInThisScan(IHttpService service) {
  return hostsToSkip.containsKey(service.getHost());
}

public void run() {
  try {
    long     start      = System.currentTimeMillis();
    ScanPool taskEngine = luancher.getTaskEngine();
    int      queueSize  = taskEngine.getQueue().size();
    utilities.out("Adding " + this.reqs.length + " tasks to queue of " + queueSize);
    queueSize += this.reqs.length;
    int                    thread_count = taskEngine.getCorePoolSize();
    ArrayList<ScanItem>    reqlist      = new ArrayList();
    IHttpRequestResponse[] var7         = this.reqs;
    int var8 = var7.length;
    
    for(int var9 = 0; var9 < var8; ++var9) {
      IHttpRequestResponse req = var7[var9];
      if (req.getRequest() == null) {
        utilities.out("Skipping null request - not sure how that got there");
      } else {
        reqlist.add(new ScanItem(req, this.config, this.scan, this.utilities));
      }
    }
    
    Collections.shuffle(reqlist);
    Collections.sort(reqlist, new SortByParentDomain());
    Set<String> keyCache = new HashSet();
    Queue<String> cache = new CircularFifoQueue(queueSize);
    HashSet<String> remainingHosts = new HashSet();
    int i = 0;
    int queued = 0;
    int prepared = 0;
    int totalRequests = reqlist.size();
    String filter = utilities.globalSettings.getString("filter");
    String respFilter = utilities.globalSettings.getString("resp-filter");
    boolean applyRespFilter = !"".equals(respFilter);
    boolean applyFilter = !"".equals(filter);
    String mimeFilter = utilities.globalSettings.getString("mimetype-filter");
    boolean applyMimeFilter = !"".equals(mimeFilter);

label124:
    for(boolean applySchemeFilter = this.config.getBoolean("filter HTTP"); !reqlist.isEmpty(); cache = new CircularFifoQueue(NumberUtils.max(new int[]{Math.min(remainingHosts.size() - 1, thread_count), 1}))) {
      utilities.out("Loop " + i++);
      ListIterator<ScanItem> left = reqlist.listIterator();
      
      while(true) {
        while(true) {
          if (!left.hasNext()) {
            continue label124;
          }
          
          boolean remove = true;
          ScanItem req = (ScanItem)left.next();
          if (applySchemeFilter && "http".equals(req.req.getHttpService().getProtocol())) {
            left.remove();
          } else if (applyFilter && !utilities.containsBytes(req.req.getRequest(), filter.getBytes())) {
            left.remove();
          } else {
            byte[] resp;
            if (applyMimeFilter) {
              resp = req.req.getResponse();
              if (resp == null) {
                if (!utilities.getHeader(req.req.getRequest(), "Accept").toLowerCase().contains(mimeFilter)) {
                  left.remove();
                  continue;
                }
              } else if (!utilities.getHeader(req.req.getResponse(), "Content-Type").toLowerCase().contains(mimeFilter)) {
                left.remove();
                continue;
              }
            }
            
            if (applyRespFilter) {
              resp = req.req.getResponse();
              if (resp == null || !utilities.containsBytes(resp, respFilter.getBytes())) {
                utilities.out("Skipping request due to response filter");
                left.remove();
                continue;
              }
            }
            
            String host = req.host;
            if (cache.contains(host)) {
              remainingHosts.add(host);
            } else {
              if (this.scan instanceof ParamScan && !req.prepared()) {
                ArrayList<ScanItem> newItems = req.prepare();
                ++prepared;
                left.remove();
                remove = false;
                if (newItems.size() == 0) {
                  continue;
                }
                
                req = (ScanItem)newItems.remove(0);
                Iterator var27 = newItems.iterator();
                
                while(var27.hasNext()) {
                  ScanItem item = (ScanItem)var27.next();
                  String key = item.getKey();
                  if (!keyCache.contains(key)) {
                    left.add(item);
                  }
                }
              }
              
              if (this.config.getBoolean("use key")) {
                String key = req.getKey();
                if (keyCache.contains(key)) {
                  if (remove) {
                    left.remove();
                  }
                  continue;
                }
                
                keyCache.add(key);
              }
              
              cache.add(host);
              if (remove) {
                left.remove();
              }
              
              utilities.out("Adding request on " + host + " to queue");
              ++queued;
              taskEngine.execute(new BulkScanItem(this.scan, req, start, utilities, luancher));
            }
          }
        }
      }
    }
    
    utilities.out("Queued " + queued + " attacks from " + totalRequests + " requests in " + (System.currentTimeMillis() - start) / 1000L + " seconds");
  } catch (Exception var30) {
    Exception e = var30;
    utilities.out("Queue aborted due to exception");
    utilities.showError(e);
  }
  
}

private Utilities utilities;
private final BulkScanLauncher luancher;
}

