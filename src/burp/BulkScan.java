package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
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

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(Scan scan) {
        taskEngine = buildTaskEngine();
        Utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scan));
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();


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


    private String getKey(IHttpRequestResponse req) {
        IRequestInfo reqInfo = Utilities.helpers.analyzeRequest(req.getRequest());

        StringBuilder key = new StringBuilder();
        key.append(req.getHttpService().getProtocol());
        key.append(req.getHttpService().getHost());

        if(  config.getBoolean("key method")) {
            key.append(reqInfo.getMethod());
        }

        if (req.getResponse() != null) {
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
                key.append(Utilities.getHeader(req.getRequest(), "Server"));
            }
        }

        return key.toString();
    }

    public void run() {
        ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        Collections.shuffle(reqlist);

        int cache_size = queueSize; //thread_count;

        Set<String> keyCache = new HashSet<>();

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        int queued = 0;

        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.log("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();
                String host = req.getHttpService().getHost();
                if (cache.contains(host)) {
                    remainingHosts.add(host);
                    continue;
                }

                if (config.getBoolean("use key")) {
                    String key = getKey(req);
                    if (keyCache.contains(key)) {
                        left.remove();
                        continue;
                    }
                    keyCache.add(key);
                }

                cache.add(host);
                left.remove();
                Utilities.log("Adding request on "+host+" to queue");
                queued++;
                taskEngine.execute(new BulkScanItem(scan, req));
            }

            cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
        }

        Utilities.out("Queued " + queued + " attacks");

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
    private Scan scan;

    OfferBulkScan(Scan scan) {
        this.scan = scan;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        JMenuItem probeButton = new JMenuItem("Launch "+scan.name);
        if(reqs != null && reqs.length > 0) {
            probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
            options.add(probeButton);
        } else if(invocation.getSelectedIssues().length > 0) {
            probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues()));
            options.add(probeButton);
        }

        return options;
    }
}

class BulkScanItem implements Runnable {

    private final IHttpRequestResponsePersisted baseReq;
    private final Scan scanner;

    BulkScanItem(Scan scanner, IHttpRequestResponse baseReq) {
        this.baseReq = Utilities.callbacks.saveBuffersToTempFiles(baseReq);
        this.scanner = scanner;
    }

    public void run() {
        scanner.doScan(baseReq.getRequest(), this.baseReq.getHttpService());
        ScanPool engine = BulkScanLauncher.getTaskEngine();
        long done = engine.getCompletedTaskCount()+1;
        Utilities.out("Completed "+ done + " of "+(engine.getQueue().size()+done));
    }
}

abstract class Scan implements IScannerCheck {
    ZgrabLoader loader = null;
    String name = "";

    Scan(String name) {
        this.name = name;
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

    static void report(String title, String detail, Resp... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        IHttpRequestResponse[] reqs = new IHttpRequestResponse[requests.length];
        for (int i=0; i<requests.length; i++) {
            reqs[i] = requests[i].getReq();
        }
        Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqs, title, detail, "High", "Tentative", "."));
    }

    Resp request(IHttpService service, byte[] req) {
        return request(service, req, 0, "");
    }

    Resp request(IHttpService service, byte[] req, int maxRetries, String comment) {
        IHttpRequestResponse resp = null;

        if (loader == null) {
            int attempts = 0;
            while (( resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
                try {
                    resp = Utilities.callbacks.makeHttpRequest(service, req);
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


class ZgrabLoader {

    private Connection conn;
    private Scan scanner;

    ZgrabLoader(Scan scanner) {
        this.scanner = scanner;

        try {
            Class.forName("org.sqlite.JDBC");
            conn = DriverManager.getConnection("jdbc:sqlite:/Users/james/PycharmProjects/zscanpipeline/requests.db");
            //Utilities.out(conn.createStatement().executeQuery("select * from requests").getString(1));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void launchSmugglePipeline() {
        String template = "POST /cowbar?x=123 HTTP/1.1\r\nHost: %d\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n";

        List<String> domains = Arrays.asList("hackxor.net", "store.unity.com", "www.redhat.com");

        scanner.setRequestMethod(this);

        for (String domain: domains) {
            byte[] request = template.replace("%d", domain).getBytes();
            IHttpService service = Utilities.callbacks.getHelpers().buildHttpService(domain, 443, true);
            scanner.doScan(request, service);
        }
        Utilities.out("Scan complete");

    }

    synchronized byte[] getResponse(String host, byte[] request) {
        try {
            PreparedStatement query = conn.prepareStatement("select domain, read from requests where domain = ? and write = ?");
            query.setString(1, host);
            query.setString(2, Utilities.helpers.bytesToString(request));
            ResultSet res = query.executeQuery();

            if (res.isClosed()) {
                Utilities.out("Couldn't find request");
                return null;
            }

            String resp = res.getString(2);
            if (resp == null) {
                Utilities.out("returning timeout...");
                return "".getBytes();
            }

            return resp.getBytes();
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }
}
