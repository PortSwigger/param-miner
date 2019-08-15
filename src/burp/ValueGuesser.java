package burp;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

class ValueGuesser implements Runnable, ActionListener {
    private ConfigurableSettings config;
    private IHttpRequestResponse[] reqs;
    private int[] selection;

    ValueGuesser(IHttpRequestResponse[] reqs, int[] selection) {
        this.reqs = reqs;
        this.selection = selection;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if (config != null) {
            this.config = config;
            (new Thread(this)).start();
        }
    }

    @Override
    public void run() {
        IScannerInsertionPoint valueInsertionPoint = new RawInsertionPoint(reqs[0].getRequest(), selection[0], selection[1]);
        PayloadInjector valueInjector = new PayloadInjector(reqs[0], valueInsertionPoint);
        String domain = reqs[0].getHttpService().getHost();

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
                break;
            }
        }

        Scan.report("Alternative code path", "details", attacks.toArray(new Resp[0]));
    }
}
