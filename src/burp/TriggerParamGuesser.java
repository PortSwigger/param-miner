package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.concurrent.ThreadPoolExecutor;

import static java.lang.Math.min;


class TriggerParamGuesser implements ActionListener, Runnable {
    private IHttpRequestResponse[] reqs;
    private boolean backend;
    private byte type;
    private ParamGrabber paramGrabber;
    private ThreadPoolExecutor taskEngine;
    private ConfigurableSettings config;

    TriggerParamGuesser(IHttpRequestResponse[] reqs, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
        this.paramGrabber = paramGrabber;
        this.backend = backend;
        this.reqs = reqs;
        this.type = type;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if (config != null) {
            this.config = config;
            //Runnable runnable = new TriggerParamGuesser(reqs, backend, type, paramGrabber, taskEngine, config);
            (new Thread(this)).start();
        }
    }

    public void run() {
        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();

        int stop = config.getInt("rotation interval");
        if (queueSize < thread_count) {
            stop = 256;
        }

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));

        int cache_size = thread_count;
        if (config.getBoolean("max one per host")) {
            cache_size = queueSize;
        }
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
            Utilities.log("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();

                if (canSkip && req.getResponse() != null && Utilities.containsBytes(req.getResponse(), noCache)) {
                    continue;
                }


                String host = req.getHttpService().getHost();

                if (!cache.contains(host)) {
                    cache.add(host);
                    left.remove();
                    Utilities.log("Adding request on "+host+" to queue");
                    queued++;
                    taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(req), backend, type, paramGrabber, taskEngine, stop, config));
                } else {
                    remainingHosts.add(host);
                }
            }

            if(config.getBoolean("max one per host")) {
                break;
            }

            if (remainingHosts.size() <= 1) {
                left = reqlist.iterator();
                while (left.hasNext()) {
                    queued++;
                    taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(left.next()), backend, type, paramGrabber, taskEngine, stop, config));
                }
                break;
            }
            else {
                cache = new CircularFifoQueue<>(min(remainingHosts.size()-1, thread_count));
            }
        }

        Utilities.out("Queued " + queued + " attacks");

    }
}