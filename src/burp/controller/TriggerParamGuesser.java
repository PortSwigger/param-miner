package burp.controller;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IResponseInfo;
import burp.model.scanning.guessing.param.ParamGrabber;
import burp.model.scanning.guessing.param.ParamGuesser;
import burp.model.utilities.Utilities;
import burp.view.ConfigurableSettings;
import org.apache.commons.collections4.queue.CircularFifoQueue;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;


public class TriggerParamGuesser implements ActionListener, Runnable {

private final Utilities              utilities;
private       IHttpRequestResponse[] reqs;
private       boolean                backend;
private       byte                   type;
private       ParamGrabber           paramGrabber;
private       ThreadPoolExecutor     taskEngine;
private       ConfigurableSettings   config;
    
    public TriggerParamGuesser(
      IHttpRequestResponse[] reqs, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine,
      Utilities utilities
    ) {
      this.taskEngine   = taskEngine;
      this.paramGrabber = paramGrabber;
      this.backend      = backend;
      this.type         = type;
      this.reqs         = reqs;
      this.utilities    = utilities;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = utilities.globalSettings.showSettings();
        if (config != null) {
            this.config = config;
            (new Thread(this)).start();
        }
    }

    public void run() {
        int queueSize = taskEngine.getQueue().size();
        utilities.out("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();

        int stop = config.getInt("rotation interval");
        if (queueSize < thread_count) {
            stop = 256;
        }

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        Collections.shuffle(reqlist);

        // If guessing smuggling mutations, downgrade HTTP/2 requests to HTTP/1.1
        if (config.getBoolean("identify smuggle mutations") && this.type == Utilities.PARAM_HEADER) {
            Iterator iterator = reqlist.iterator();
            for (int i = 0; i < reqlist.size(); i++) {
                IHttpRequestResponse req = reqlist.get(i);
                if (!Utilities.isHTTP2(req.getRequest())) {
                    continue;
                }
                byte[] downgraded = Utilities.convertToHttp1(req.getRequest());
                String host = req.getHttpService().getHost();
                int port = req.getHttpService().getPort();
                String       proto   = req.getHttpService().getProtocol();
                IHttpService service = utilities.helpers.buildHttpService(host, port, proto);

                IHttpRequestResponse newReq = utilities.attemptRequest(service, downgraded, true);
                reqlist.set(i, newReq);
                this.reqs[i] = newReq;
            }
        }

        int cache_size = thread_count;
        if (config.getBoolean("max one per host")) {
            cache_size = queueSize;
        }

        Set<String> keyCache = new HashSet<>();
        boolean useKeyCache = config.getBoolean("max one per host+status");

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        boolean canSkip = false;
        byte[] noCache = "no-cache".getBytes();
        if (config.getBoolean("skip uncacheable") && (type == IParameter.PARAM_COOKIE || type == Utilities.PARAM_HEADER)) {
            canSkip = true;
        }


        int i = 0;
        int queued = 0;
        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            utilities.out("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();

                String host = req.getHttpService().getHost();
                String key = req.getHttpService().getProtocol()+host;
                if (req.getResponse() != null) {
                    if (canSkip && utilities.containsBytes(req.getResponse(), noCache)) {
                        continue;
                    }

                    IResponseInfo info = utilities.helpers.analyzeResponse(req.getResponse());
                    key = key + info.getStatusCode() + info.getInferredMimeType();
                }

                if (useKeyCache && keyCache.contains(key)) {
                    left.remove();
                    continue;
                }

                if (!cache.contains(host)) {
                    cache.add(host);
                    keyCache.add(key);
                    left.remove();
                    utilities.out("Adding request on "+host+" to queue");
                    queued++;
                    taskEngine.execute(new ParamGuesser(utilities.callbacks.saveBuffersToTempFiles(req), backend, type, paramGrabber, taskEngine, stop, config, utilities));
                } else {
                    remainingHosts.add(host);
                }
            }

            if(config.getBoolean("max one per host")) {
                break;
            }

            if (remainingHosts.size() <= 1 && !useKeyCache) {
                left = reqlist.iterator();
                while (left.hasNext()) {
                    queued++;
                    taskEngine.execute(new ParamGuesser(utilities.callbacks.saveBuffersToTempFiles(left.next()), backend, type, paramGrabber, taskEngine, stop, config, utilities));
                }
                break;
            }
            else {
                cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
            }
        }

        utilities.out("Queued " + queued + " attacks");
    }
}