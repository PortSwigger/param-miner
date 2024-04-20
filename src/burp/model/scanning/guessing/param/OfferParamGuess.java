package burp.model.scanning.guessing.param;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.controller.TriggerParamGuesser;
import burp.model.utilities.misc.Utilities;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;

public class OfferParamGuess implements IContextMenuFactory {
private final Utilities              utilities;
private final ParamGrabber           paramGrabber;
private final ThreadPoolExecutor     taskEngine;

public OfferParamGuess(ParamGrabber paramGrabber, ThreadPoolExecutor taskEngine, Utilities utilities) {
      this.taskEngine   = taskEngine;
      this.paramGrabber = paramGrabber;
      this.utilities    = utilities;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs    = invocation.getSelectedMessages();
        List<JMenuItem>        options = new ArrayList<>();

        if(reqs == null || reqs.length == 0) {
            if (invocation.getSelectedIssues().length > 0) {
                ArrayList<IHttpRequestResponse> newReqs = new ArrayList<>();
                for(IScanIssue issue: invocation.getSelectedIssues()){
                    newReqs.add(issue.getHttpMessages()[0]);

                }
                reqs = newReqs.toArray(new IHttpRequestResponse[0]);
            }
            else {
                return options;
            }
        }

        JMenu scanMenu = new JMenu("Guess params");

        JMenuItem allButton = new JMenuItem("Guess everything!");
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine, utilities));
        
        JMenuItem probeButton = new JMenuItem("Guess GET parameters");
        probeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine, utilities));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_URL, paramGrabber, taskEngine, utilities));
        scanMenu.add(probeButton);

        JMenuItem cookieProbeButton = new JMenuItem("Guess cookie parameters");
        cookieProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_COOKIE, paramGrabber, taskEngine, utilities));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, IParameter.PARAM_COOKIE, paramGrabber, taskEngine, utilities));
        scanMenu.add(cookieProbeButton);

        JMenuItem headerProbeButton = new JMenuItem("Guess headers");
        headerProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, Utilities.PARAM_HEADER, paramGrabber, taskEngine, utilities));
        allButton.addActionListener(new TriggerParamGuesser(reqs, false, Utilities.PARAM_HEADER, paramGrabber, taskEngine, utilities));
        scanMenu.add(headerProbeButton);

//        if (invocation.getSelectionBounds() != null && reqs.length == 1) {
//            JMenuItem valueProbeButton = new JMenuItem("Guess value");
//            valueProbeButton.addActionListener(new ValueGuesser(reqs, invocation.getSelectionBounds()));
//            options.add(valueProbeButton);
//        }


        if (reqs.length == 1 && reqs[0] != null) {
            IHttpRequestResponse req = reqs[0];
            byte[] resp = req.getRequest();
            if (Utilities.countMatches(resp, utilities.helpers.stringToBytes("%253c%2561%2560%2527%2522%2524%257b%257b%255c")) > 0) {
                JMenuItem backendProbeButton = new JMenuItem("*Identify backend parameters*");
                backendProbeButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber, taskEngine, utilities));
                allButton.addActionListener(new TriggerParamGuesser(reqs, true, IParameter.PARAM_URL, paramGrabber, taskEngine, utilities));
                scanMenu.add(backendProbeButton);
            }

//            if (utilities.containsBytes(resp, "HTTP/1.1".getBytes())) {
//                JMenuItem tunHeaderProbeButton = new JMenuItem("Guess tunneled headers");
//                tunHeaderProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, utilities.PARAM_HEADER_TUNNELED, paramGrabber, taskEngine, utilities));
//                allButton.addActionListener(new TriggerParamGuesser(reqs, false, utilities.PARAM_HEADER_TUNNELED, paramGrabber, taskEngine, utilities));
//                options.add(tunHeaderProbeButton);
//            }

            if (resp != null && resp.length > 0 && resp[0] == 'P') {
                IRequestInfo     info   = utilities.helpers.analyzeRequest(req);
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
                    postProbeButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber, taskEngine, utilities));
                    allButton.addActionListener(new TriggerParamGuesser(reqs, false, type, paramGrabber, taskEngine, utilities));
                    scanMenu.add(postProbeButton);
                }
            }
        }

        scanMenu.add(allButton);
        options.add(scanMenu);
        return options;
    }
}
