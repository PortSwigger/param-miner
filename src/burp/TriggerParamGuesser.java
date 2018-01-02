package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

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

    TriggerParamGuesser(IHttpRequestResponse[] reqs, boolean backend, byte type, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
        this.paramGrabber = paramGrabber;
        this.backend = backend;
        this.reqs = reqs;
        this.type = type;
    }

    public void actionPerformed(ActionEvent e) {
        Runnable runnable = new TriggerParamGuesser(reqs, backend, type, paramGrabber, taskEngine);
        (new Thread(runnable)).start();
    }

    public void run() {
        Utilities.log("Queuing "+reqs.length+" tasks");

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        int thread_count = taskEngine.getCorePoolSize();
        Queue<String> cache = new CircularFifoQueue<>(thread_count);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.log("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();
                String host = req.getHttpService().getHost();

                if (!cache.contains(host)) {
                    cache.add(host);
                    left.remove();
                    Utilities.log("Adding request on "+host+" to queue");
                    taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(req), backend, type, paramGrabber, taskEngine, 0, 20));
                } else {
                    remainingHosts.add(host);
                }
            }
            if (remainingHosts.size() <= 1) {
                left = reqlist.iterator();
                while (left.hasNext()) {
                    taskEngine.execute(new ParamGuesser(Utilities.callbacks.saveBuffersToTempFiles(left.next()), backend, type, paramGrabber, taskEngine, 0, 20));
                }
                break;
            }
            else {
                cache = new CircularFifoQueue<>(min(remainingHosts.size()-1, thread_count));
            }
        }

    }
}