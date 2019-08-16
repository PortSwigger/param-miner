package burp;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class ValueGuesser implements Runnable, ActionListener {
    private IHttpRequestResponse[] reqs;
    private int[] selection;

    ValueGuesser(IHttpRequestResponse[] reqs, int[] selection) {
        this.reqs = reqs;
        this.selection = selection;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if (config != null) {
            (new Thread(this)).start();
        }
    }

    static void guessValue(IHttpRequestResponse req, int start, int end) {
        IScannerInsertionPoint valueInsertionPoint = new RawInsertionPoint(req.getRequest(), start, end);
        guessValue(req, valueInsertionPoint);
    }


    static void guessValue(IHttpRequestResponse req, IScannerInsertionPoint valueInsertionPoint) {
        PayloadInjector valueInjector = new PayloadInjector(req, valueInsertionPoint);
        String domain = req.getHttpService().getHost();

        Attack randBase = valueInjector.probeAttack(Utilities.generateCanary());
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));
        randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));

        String baseValue = "wrtqvetc";
        ArrayList<String> potentialValues = new ArrayList<>();
        // order by severity?
        potentialValues.add("0");
        potentialValues.add("1");
        potentialValues.add("false");
        potentialValues.add("true");
        potentialValues.add("/cow");
        potentialValues.add("https://"+domain+"/");
        potentialValues.add("test@"+domain);
        potentialValues.add("{}");
        potentialValues.add("[]");
        potentialValues.add("`z'z\"${{%{{\\");
        // todo try observed values, wordlists etc
        // todo multi-step exploration? number->observed numbers

        ArrayList<Resp> attacks = new ArrayList<>();
        attacks.add(new Resp(randBase.getFirstRequest()));

        for (String potentialValue : potentialValues) {
            int count = 0;

            Attack potentialBase = null;
            for(;count<5;count++) {
                potentialBase = valueInjector.probeAttack(potentialValue);
                if (Utilities.similar(randBase, potentialBase)) {
                    break;
                }
                randBase.addAttack(valueInjector.probeAttack(Utilities.generateCanary()));
                if (Utilities.similar(randBase, potentialBase)) {
                    break;
                }
            }

            if (count == 5) {
                baseValue = potentialValue;
                Utilities.out("Alternative code path triggered by value '"+baseValue+"'");
                attacks.add(new Resp(potentialBase.getFirstRequest()));
            }
        }

        if (attacks.size() > 1) {
            Scan.report("Alternative code path", "details", attacks.toArray(new Resp[0]));
            // Utilities.doActiveScan(Utilities.attemptRequest(injector.getService(), valueInsertionPoint.buildRequest(baseValue.getBytes())), valueInsertionPoint.getPayloadOffsets(baseValue.getBytes()));
        }
    }

    @Override
    public void run() {
        guessValue(reqs[0], selection[0], selection[1]);
    }
}

class ValueScan extends ParamScan {

    ValueScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        return null;
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseReq, IScannerInsertionPoint insertionPoint) {
        ValueGuesser.guessValue(baseReq, insertionPoint);
        return null;
    }
}