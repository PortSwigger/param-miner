package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;

class OfferParamGuess implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private ParamGrabber paramGrabber;
    private ThreadPoolExecutor taskEngine;

    public OfferParamGuess(final IBurpExtenderCallbacks callbacks, ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine) {
        this.taskEngine = taskEngine;
        this.callbacks = callbacks;
        this.paramGrabber = paramGrabber;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        if(reqs == null || reqs.length == 0) {
            return options;
        }

        JMenuItem allButton = new JMenuItem("Guess everything!");
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine));
        
        JMenuItem probeButton = new JMenuItem("Guess GET parameters");
        probeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine));
        options.add(probeButton);

        JMenuItem cookieProbeButton = new JMenuItem("Guess cookie parameters");
        cookieProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_COOKIE, paramGrabber, taskEngine));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_COOKIE, paramGrabber, taskEngine));
        options.add(cookieProbeButton);

        JMenuItem headerProbeButton = new JMenuItem("Guess headers");
        headerProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, Utilities.PARAM_HEADER, paramGrabber, taskEngine));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, Utilities.PARAM_HEADER, paramGrabber, taskEngine));
        options.add(headerProbeButton);

//        if (invocation.getSelectionBounds() != null && reqs.length == 1) {
//            JMenuItem valueProbeButton = new JMenuItem("Guess value");
//            valueProbeButton.addActionListener(new ValueGuesser(reqs, invocation.getSelectionBounds()));
//            options.add(valueProbeButton);
//        }


        if (reqs.length == 1 && reqs[0] != null) {
            IHttpRequestResponse req = reqs[0];
            byte[] resp = req.getRequest();
            if (Utilities.countMatches(resp, Utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
                JMenuItem backendProbeButton = new JMenuItem("*Identify backend parameters*");
                backendProbeButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber, taskEngine));
                allButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber, taskEngine));
                options.add(backendProbeButton);
            }

            if (resp != null && resp.length > 0 && resp[0] == 'P') {
                IRequestInfo info = Utilities.helpers.analyzeRequest(req);
                List<IParameter> params = info.getParameters();

                HashSet<Byte> paramTypes = new HashSet<>();
                for (IParameter param : params) {
                    if (param.getType() != IParameter.PARAM_URL) {
                        paramTypes.add(param.getType());
                    }
                }

                for (Byte type : paramTypes) {
                    String humanType = "Unknown";
                    switch(type) {
                        case 0:
                            humanType = "URL";
                            break;
                        case 1:
                            humanType = "body";
                            break;
                        case 2:
                            humanType = "cookie";
                            continue;
                        case 3:
                            humanType = "XML";
                            break;
                        case 4:
                            humanType = "XML attribute";
                            break;
                        case 5:
                            humanType = "multipart";
                            break;
                        case 6:
                            humanType = "JSON";
                            break;
                    }

                    JMenuItem postProbeButton = new JMenuItem("Guess " + humanType + " parameter");
                    postProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber, taskEngine));
                    allButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber, taskEngine));
                    options.add(postProbeButton);
                }
            }
        }

        options.add(allButton);
        return options;
    }
}
