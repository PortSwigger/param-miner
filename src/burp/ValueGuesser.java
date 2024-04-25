package burp;


import burp.albinowaxUtils.Attack;
import burp.albinowaxUtils.ConfigurableSettings;
import burp.albinowaxUtils.PayloadInjector;
import burp.albinowaxUtils.RawInsertionPoint;
import burp.albinowaxUtils.Resp;
import burp.albinowaxUtils.Scan;
import burp.albinowaxUtils.Utilities;
import org.apache.commons.lang3.StringUtils;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

class ValueGuesser implements Runnable, ActionListener {
    private IHttpRequestResponse[] reqs;
    private       int[]     selection;
    private final Utilities utilities;
    
    ValueGuesser(IHttpRequestResponse[] reqs, int[] selection, Utilities utilities) {
        this.reqs = reqs;
        this.selection = selection;
        this.utilities = utilities;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = utilities.globalSettings.showSettings();
        if (config != null) {
            (new Thread(this)).start();
        }
    }

    void guessValue(IHttpRequestResponse req, int start, int end) {
        IScannerInsertionPoint valueInsertionPoint = new RawInsertionPoint(req.getRequest(), "name", start, end);
        guessValue(req, valueInsertionPoint);
    }


    void guessValue(IHttpRequestResponse req, IScannerInsertionPoint valueInsertionPoint) {
        PayloadInjector valueInjector = new PayloadInjector(req, valueInsertionPoint, utilities);
        IHttpService    service       = req.getHttpService();
        String domain = service.getHost();

        Attack randBase = valueInjector.probeAttack(utilities.generateCanary());
        randBase.addAttack(valueInjector.probeAttack(utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(utilities.generateCanary()));

        String baseValue = valueInsertionPoint.getBaseValue();
        ArrayList<String> potentialValues = new ArrayList<>();

        // todo try observed values, wordlists etc
        // todo multi-step exploration? number->observed numbers
        potentialValues.add("z"); // false positive catcher

        if (!StringUtils.isNumeric(baseValue)) {
            potentialValues.add("1");
            //potentialValues.add("0");
        }

        if (!baseValue.equals("true") && !baseValue.equals("false")) {
            potentialValues.add("true");
            //potentialValues.add("false");
        }

        if (!baseValue.startsWith("/") && !baseValue.startsWith("http")) {
            potentialValues.add("/cow");
            potentialValues.add("https://"+domain+"/");
        }

        if (!baseValue.contains("@")) {
            potentialValues.add("test@" + domain);
        }

        if (!baseValue.startsWith("{") && !baseValue.startsWith("[")) {
            potentialValues.add("{}");
            potentialValues.add("[]");
        }

        potentialValues.add("`z'z\"${{\\"); // removed % because it isn't getting URL-encoded


        ArrayList<Resp> attacks = new ArrayList<>();
        attacks.add(new Resp(randBase.getFirstRequest(), utilities));

        boolean launchedScan = false;
        String title = "Alternative code path";
        for (String potentialValue : potentialValues) {
            int count = 0;

            Attack potentialBase = null;
            for(;count<5;count++) {
                potentialBase = valueInjector.probeAttack(potentialValue);
                if (utilities.similar(randBase, potentialBase)) {
                    break;
                }
                randBase.addAttack(valueInjector.probeAttack(utilities.generateCanary()));
                if (utilities.similar(randBase, potentialBase)) {
                    break;
                }

                Object status = potentialBase.getPrint().get("status_code");
                if(status != null && "400".equals(status.toString())) {
                    break;
                }

            }

            if (count == 5) {


                baseValue = potentialValue;
                utilities.out("Alternative code path triggered by value '"+baseValue+"'");
                IHttpRequestResponse altBase = valueInjector.buildRequest(potentialValue, false);//potentialBase.getFirstRequest();
                attacks.add(new Resp(altBase, utilities));

                if (potentialValue.equals("z")) {
                    title = "Fake code path";
                    break;
                }



                if (!launchedScan) {
                    // scan this insertion point with our new base value
                    // utilities.doActiveScan(utilities.attemptRequest(service, newBaseRequest), valueInsertionPoint.getPayloadOffsets(baseValue.getBytes()));

                    // scan the entire request with our new base value
                    title = "Alternative code path: "+potentialValue;
                    utilities.callbacks.doActiveScan(domain, service.getPort(), utilities.isHTTPS(service), altBase.getRequest());
                    launchedScan = true;
                }
            }
        }

        if (false && attacks.size() > 1) {
            title += "#"+(attacks.size()-1);
            Scan.report(title, "details", utilities, attacks.toArray(new Resp[0]));
        }
    }

    @Override
    public void run() {
        guessValue(reqs[0], selection[0], selection[1]);
    }
}


// todo: this was never used, what was it for?
//class ValueScan extends ParamScan {
//
//    ValueScan(String name) {
//        super(name);
//    }
//
//    @Override
//    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
//        return null;
//    }
//
//    @Override
//    public List<IScanIssue> doScan(IHttpRequestResponse baseReq, IScannerInsertionPoint insertionPoint) {
//        ValueGuesser.guessValue(baseReq, insertionPoint);
//        return null;
//    }
//}