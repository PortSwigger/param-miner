package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(List<Scan> scans) {
        taskEngine = buildTaskEngine();
        Utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scans));
    }

    static void registerDefaults() {
        Utilities.globalSettings.registerSetting("thread pool size", 8);
        Utilities.globalSettings.registerSetting("use key", true);
        Utilities.globalSettings.registerSetting("key method", true);
        Utilities.globalSettings.registerSetting("key status", true);
        Utilities.globalSettings.registerSetting("key content-type", true);
        Utilities.globalSettings.registerSetting("key server", true);
        Utilities.globalSettings.registerSetting("key header names", false);
        Utilities.globalSettings.registerSetting("param-scan cookies", false);
        Utilities.globalSettings.registerSetting("filter", "");
        Utilities.globalSettings.registerSetting("mimetype-filter", "");
        Utilities.globalSettings.registerSetting("resp-filter", "");
        Utilities.globalSettings.registerSetting("add dummy param", false);
        Utilities.globalSettings.registerSetting("dummy param name", "utm_campaign");
        Utilities.globalSettings.registerSetting("confirmations", 5);
        Utilities.globalSettings.registerSetting("report tentative", true);
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();

        registerDefaults();

        ScanPool taskEngine = new ScanPool(Utilities.globalSettings.getInt("thread pool size"), Utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        Utilities.globalSettings.registerListener("thread pool size", value -> {
            Utilities.out("Updating active thread pool size to "+value);
            try {
                taskEngine.setCorePoolSize(Integer.parseInt(value));
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
            } catch (IllegalArgumentException e) {
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
                taskEngine.setCorePoolSize(Integer.parseInt(value));
            }
        });
        return taskEngine;
    }

    static ScanPool getTaskEngine() {
        return taskEngine;
    }
}

class BulkScan implements Runnable  {
    private IHttpRequestResponse[] reqs;
    private Scan scan;
    private ConfigurableSettings config;

    BulkScan(Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config) {
        this.scan = scan;
        this.reqs = reqs;
        this.config = config;
    }

    public void run() {
        long start = System.currentTimeMillis();
        ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();


        //ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));

        ArrayList<ScanItem> reqlist = new ArrayList<>();
        for (IHttpRequestResponse req: reqs) {
            reqlist.add(new ScanItem(req, config, scan));
        }
        Collections.shuffle(reqlist);

        int cache_size = queueSize; //thread_count;

        Set<String> keyCache = new HashSet<>();

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        int queued = 0;
        boolean remove;
        int prepared = 0;
        int totalRequests = reqlist.size();
        String filter = Utilities.globalSettings.getString("filter");
        String respFilter = Utilities.globalSettings.getString("resp-filter");
        boolean applyRespFilter = !"".equals(respFilter);
        boolean applyFilter = !"".equals(filter);
        String mimeFilter = Utilities.globalSettings.getString("mimetype-filter");
        boolean applyMimeFilter = !"".equals(mimeFilter);

        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.out("Loop "+i++);
            ListIterator<ScanItem> left = reqlist.listIterator();
            while (left.hasNext()) {
                remove = true;
                ScanItem req = left.next();


                if (applyFilter && !Utilities.containsBytes(req.req.getRequest(), filter.getBytes())) {
                    left.remove();
                    continue;
                }

                if (applyMimeFilter) {
                    byte[] resp = req.req.getResponse();
                    if (resp == null) {
                        if (!Utilities.getHeader(req.req.getRequest(), "Accept").toLowerCase().contains(mimeFilter)) {
                            left.remove();
                            continue;
                        }
                    }
                    else {
                        if (!Utilities.getHeader(req.req.getResponse(), "Content-Type").toLowerCase().contains(mimeFilter)) {
                            left.remove();
                            continue;
                        }
                    }
                }

                // fixme doesn't actually work - maybe the resp is always null?
                if (applyRespFilter) {
                    byte[] resp = req.req.getResponse();
                    if (resp == null || !Utilities.containsBytes(resp, respFilter.getBytes())) {
                        Utilities.log("Skipping request due to response filter");
                        left.remove();
                        continue;
                    }
                }

                String host = req.host;
                if (cache.contains(host)) {
                    remainingHosts.add(host);
                    continue;
                }


                if (scan instanceof ParamScan && !req.prepared()) {
                    ArrayList<ScanItem> newItems = req.prepare();
                    Utilities.log("Prepared "+prepared + " of "+totalRequests);
                    prepared++;
                    left.remove();
                    remove = false;
                    if (newItems.size() == 0) {
                        continue;
                    }
                    req = newItems.remove(0);
                    for (ScanItem item: newItems) {
                        if(!keyCache.contains(item.getKey())) {
                            left.add(item);
                        }
                    }
                }

                if (config.getBoolean("use key")) {
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
                Utilities.log("Adding request on "+host+" to queue");
                queued++;
                taskEngine.execute(new BulkScanItem(scan, req));
            }

            cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
        }

        Utilities.out("Queued " + queued + " attacks from "+ totalRequests + " requests in "+(System.currentTimeMillis()-start)/100+" seconds");
    }
}

class ScanItem {
    private Scan scan;
    IHttpRequestResponse req;
    String host;
    private ConfigurableSettings config;
    private boolean prepared = false;
    IScannerInsertionPoint insertionPoint;
    private IParameter param;
    private String key = null;
    String method = null;


    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.scan = scan;
    }

    ScanItem(IHttpRequestResponse req, ConfigurableSettings config, Scan scan, IParameter param) {
        this.req = req;
        this.host = req.getHttpService().getHost();
        this.config = config;
        this.param = param;
        insertionPoint = new RawInsertionPoint(req.getRequest(), param.getName(), param.getValueStart(), param.getValueEnd());
        this.prepared = true;
        this.scan = scan;
    }

    boolean prepared() {
        return prepared;
    }

    ArrayList<ScanItem> prepare() {
        ArrayList<ScanItem> items = new ArrayList<>();

        method = Utilities.getMethod(req.getRequest());

// no longer required as the filter is done earlier
//        String filterValue = Utilities.globalSettings.getString("filter");
//        if (!"".equals(filterValue)) {
//            if (req.getResponse() == null || !Utilities.containsBytes(req.getResponse(), filterValue.getBytes())) {
//                return items;
//            }
//        }

        // don't waste time analysing GET requests with no = in the request line
        if (!Utilities.getPathFromRequest(req.getRequest()).contains("=")) {
            if (!Utilities.globalSettings.getBoolean("add dummy param")) {
                prepared = true;
                return items;
            }

            // if you use setRequest instead, it will overwrite the original!
            // fixme somehow triggers a stackOverflow
        }

        if (Utilities.globalSettings.getBoolean("add dummy param")) {
            req = new Req(Utilities.appendToQuery(req.getRequest(), Utilities.globalSettings.getString("dummy param name")+"=z"), req.getResponse(), req.getHttpService());
        }

        // analyzeRequest is really slow
        //reqInfo = Utilities.helpers.analyzeRequest(req);
        //ArrayList<IParameter> params = new ArrayList<>(reqInfo.getParameters());
        // fixme why is this null?
        ArrayList<PartialParam> params = Utilities.getParams(req.getRequest());

        // Utilities.globalSettings.getBoolean("param-scan cookies")
        for (IParameter param: params) {
            if (param.getType() != IParameter.PARAM_URL) {
                continue;
            }
            items.add(new ScanItem(req, config, scan, param));
        }
        prepared = true;
        return items;
    }

    String getKey() {

        if (method == null) {
            method = Utilities.getMethod(req.getRequest());
        }

        if (key != null) {
            return key;
        }

        StringBuilder key = new StringBuilder();
        key.append(req.getHttpService().getProtocol());
        key.append(req.getHttpService().getHost());

        if (scan instanceof ParamScan) {
            key.append(param.getName());
            key.append(param.getType());
        }

        if(config.getBoolean("key method")) {
            key.append(method);
        }

        if (req.getResponse() != null && (config.getBoolean("key header names") || config.getBoolean("key status") || config.getBoolean("key content-type") || config.getBoolean("key server"))) {
            IResponseInfo respInfo = Utilities.helpers.analyzeResponse(req.getResponse());

            if (config.getBoolean("key header names")) {
                StringBuilder headerNames = new StringBuilder();
                for (String header : respInfo.getHeaders()) {
                    headerNames.append(header.split(": ")[0]);
                }
                key.append(headerNames.toString());
            }

            if (config.getBoolean("key status")) {
                key.append(respInfo.getStatusCode());
            }

            if (config.getBoolean("key content-type")) {
                key.append(respInfo.getStatedMimeType());
            }

            if (config.getBoolean("key server")) {
                key.append(Utilities.getHeader(req.getResponse(), "Server"));
            }
        }

        this.key = key.toString();

        return this.key;
    }

}

class TriggerBulkScan implements ActionListener {

    private IHttpRequestResponse[] reqs;
    private IScanIssue[] issues;
    private Scan scan;

    TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs) {
        this.scan = scan;
        this.reqs = reqs;
    }

    TriggerBulkScan(Scan scan, IScanIssue[] issues) {
        this.scan = scan;
        this.issues = issues;
    }

    public void actionPerformed(ActionEvent e) {
        if (this.reqs == null) {
            this.reqs = new IHttpRequestResponse[issues.length];
            for (int i=0; i<issues.length; i++) {
                IScanIssue issue = issues[i];
                reqs[i] = new Req(Utilities.helpers.buildHttpRequest(issue.getUrl()), null, issue.getHttpService());
            }
        }

        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if (config != null) {
            BulkScan bulkScan = new BulkScan(scan, reqs, config);
            (new Thread(bulkScan)).start();
        }
    }
}

class OfferBulkScan implements IContextMenuFactory {
    private List<Scan> scans;

    OfferBulkScan(List<Scan> scans) {
        this.scans = scans;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        JMenu scanMenu = new JMenu("Bulk Scan");

        if (reqs != null && reqs.length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
                scanMenu.add(probeButton);
            }
        } else if (invocation.getSelectedIssues().length > 0) {
            for (Scan scan : scans) {
                JMenuItem probeButton = new JMenuItem(scan.name);
                probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues()));
                scanMenu.add(probeButton);
            }
        }

        options.add(scanMenu);
        return options;
    }
}

class BulkScanItem implements Runnable {

    private final ScanItem baseItem;
    private final IHttpRequestResponsePersisted baseReq;
    private final Scan scanner;

    BulkScanItem(Scan scanner, ScanItem baseReq) {
        this.baseReq = Utilities.callbacks.saveBuffersToTempFiles(baseReq.req);
        this.baseItem = baseReq;
        this.scanner = scanner;
    }

    public void run() {
        if (scanner instanceof ParamScan) {
            scanner.doActiveScan(baseReq, baseItem.insertionPoint);
        }
        else {
            scanner.doScan(baseReq.getRequest(), this.baseReq.getHttpService());
        }
        ScanPool engine = BulkScanLauncher.getTaskEngine();
        long done = engine.getCompletedTaskCount()+1;
        Utilities.out("Completed "+ done + " of "+(engine.getQueue().size()+done) + " with "+Utilities.requestCount.get()+" requests, "+engine.candidates + " candidates and "+engine.findings + " findings ");
    }
}


abstract class ParamScan extends Scan {
    public ParamScan(String name) {
        super(name);
    }

    abstract List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // todo convert insertion point into appropriate format
        return doScan(baseRequestResponse, insertionPoint);
    }

}

abstract class Scan implements IScannerCheck {
    ZgrabLoader loader = null;
    String name = "";

    Scan(String name) {
        this.name = name;
        BurpExtender.scans.add(this);
        //Utilities.callbacks.registerScannerCheck(this);
    }

    abstract List<IScanIssue> doScan(byte[] baseReq, IHttpService service);

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    void setRequestMethod(ZgrabLoader loader) {
        this.loader = loader;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    static void recordCandidateFound() {
        BulkScanLauncher.getTaskEngine().candidates.incrementAndGet();
    }

    static void report(String title, String detail, Resp... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        IHttpRequestResponse[] reqs = new IHttpRequestResponse[requests.length];
        for (int i=0; i<requests.length; i++) {
            reqs[i] = requests[i].getReq();
        }
        if (Utilities.isBurpPro()) {
            Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqs, title, detail, "High", "Tentative", "."));
        } else {
            StringBuilder serialisedIssue = new StringBuilder();
            serialisedIssue.append("Found issue: ");
            serialisedIssue.append(title);
            serialisedIssue.append("\n");
            serialisedIssue.append("Target: ");
            serialisedIssue.append(service.getProtocol());
            serialisedIssue.append("://");
            serialisedIssue.append(service.getHost());
            serialisedIssue.append("\n");
            serialisedIssue.append(detail);
            serialisedIssue.append("\n");
            serialisedIssue.append("Evidence: \n======================================\n");
            for (IHttpRequestResponse req: reqs) {
                serialisedIssue.append(Utilities.helpers.bytesToString(req.getRequest()));
//                serialisedIssue.append("\n--------------------------------------\n");
//                if (req.getResponse() == null) {
//                    serialisedIssue.append("[no response]");
//                }
//                else {
//                    serialisedIssue.append(Utilities.helpers.bytesToString(req.getResponse()));
//                }
                serialisedIssue.append("\n======================================\n");
            }

            Utilities.out(serialisedIssue.toString());
        }
    }

    Resp request(IHttpService service, byte[] req) {
        return request(service, req, 0, "");
    }

    Resp request(IHttpService service, byte[] req, int maxRetries, String comment) {
        if (Utilities.unloaded.get()) {
            throw new RuntimeException("Unloaded - aborting request");
        }

        IHttpRequestResponse resp = null;

        if (loader == null) {
            int attempts = 0;
            while (( resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
                try {
                    resp = Utilities.callbacks.makeHttpRequest(service, req);

//                    TurboEngine engine = new TurboEngine(service);
//                    engine.queue(req);
//                    resp = engine.waitFor().get(0).getReq();
                } catch (java.lang.RuntimeException e) {
                    Utilities.out("Recovering from request exception");
                    Utilities.err("Recovering from request exception");
                    resp = new Req(req, null, service);
                }
                attempts += 1;
            }
        }
        else {
            byte[] response = loader.getResponse(service.getHost(), req);
            if (response == null) {
                try {
                    String template = Utilities.helpers.bytesToString(req).replace(service.getHost(), "%d");
                    String name = Integer.toHexString(template.hashCode());
                    PrintWriter out = new PrintWriter("/Users/james/PycharmProjects/zscanpipeline/generated-requests/"+name);
                    out.print(template);
                    out.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }

                Utilities.out("Couldn't find response. Sending via Burp instead");
                Utilities.out(Utilities.helpers.bytesToString(req));
                return new Resp(Utilities.callbacks.makeHttpRequest(service, req));
                //throw new RuntimeException("Couldn't find response");
            }

            if (Arrays.equals(response, "".getBytes())) {
                response = null;
            }

            resp = new Req(req, response, service);
        }

        return new Resp(resp, comment);
    }
}

class ScanPool extends ThreadPoolExecutor implements IExtensionStateListener {

    AtomicInteger candidates = new AtomicInteger(0);
    AtomicInteger findings = new AtomicInteger(0);

    ScanPool(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        getQueue().clear();
        shutdown();
    }
}

class Resp {
    private IHttpRequestResponse req;
    private IResponseInfo info;
    private IResponseVariations attributes;
    String comment = "";

    public long getTimestamp() {
        return timestamp;
    }

    private long timestamp;

    public short getStatus() {
        return status;
    }

    private short status = 0;
    private boolean timedOut;

    Resp(IHttpRequestResponse req, String comment) {
        this(req);
        this.comment = comment;
    }

    Resp(IHttpRequestResponse req) {
        this.timestamp = System.currentTimeMillis();
        this.req = req;
        this.timedOut = req.getResponse() == null;
        if (!timedOut) {
            this.info = Utilities.helpers.analyzeResponse(req.getResponse());
            this.attributes = Utilities.helpers.analyzeResponseVariations(req.getResponse());
            this.status = this.info.getStatusCode();
        }
    }

    IHttpRequestResponse getReq() {
        return req;
    }

    IResponseInfo getInfo() {
        return info;
    }

    IResponseVariations getAttributes() {
        return attributes;
    }

    boolean timedOut() {
        return timedOut;
    }
}

class Req implements IHttpRequestResponse {

    private byte[] req;
    private byte[] resp;
    private IHttpService service;

    Req(byte[] req, byte[] resp, IHttpService service) {
        this.req = req;
        this.resp = resp;
        this.service = service;
    }

    @Override
    public byte[] getRequest() {
        return req;
    }

    @Override
    public void setRequest(byte[] message) {
        this.req = message;
    }

    @Override
    public byte[] getResponse() {
        return resp;
    }

    @Override
    public void setResponse(byte[] message) {
        this.resp = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service = httpService;
    }

//    @Override
//    public String getHost() {
//        return service.getHost();
//    }
//
//    @Override
//    public int getPort() {
//        return service.getPort();
//    }
//
//    @Override
//    public String getProtocol() {
//        return service.getProtocol();
//    }
//
//    @Override
//    public void setHost(String s) {
//
//    }
//
//    @Override
//    public void setPort(int i) {
//
//    }
//
//    @Override
//    public void setProtocol(String s) {
//
//    }
//
//    @Override
//    public URL getUrl() {
//        return Utilities.getURL(req, service);
//    }
//
//    @Override
//    public short getStatusCode() {
//        return 0;
//    }
}

class RawInsertionPoint implements IScannerInsertionPoint {
    private byte[] prefix;
    private byte[] suffix;
    private String baseValue;
    private String name;

    RawInsertionPoint(byte[] req, String name, int start, int end) {
        this.name = name;
        this.prefix = Arrays.copyOfRange(req, 0, start);
        this.suffix = Arrays.copyOfRange(req, end, req.length);
        baseValue = new String(Arrays.copyOfRange(req, start, end));
    }


    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public String getBaseValue() {
        return baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(prefix);
            outputStream.write(payload);
            outputStream.write(suffix);
        } catch (IOException e) {

        }

        return Utilities.fixContentLength(outputStream.toByteArray());
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        return new int[]{prefix.length, prefix.length+payload.length};
    }

    @Override
    public byte getInsertionPointType() {
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}

class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[1];
        this.httpMessages[0] = httpMessages;

        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }
}
