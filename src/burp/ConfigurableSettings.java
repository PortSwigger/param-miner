package burp;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.LinkedHashMap;

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener{
    private JMenu menuButton;

    ConfigMenu() {
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    public void run()
    {
        menuButton = new JMenu("Param Miner");
        menuButton.addMenuListener(this);
        JMenuBar burpMenuBar = Utilities.getBurpFrame().getJMenuBar();
        burpMenuBar.add(menuButton);
    }

    public void menuSelected(MenuEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run(){
                Utilities.globalSettings.showSettings();
            }
        });
    }

    public void menuDeselected(MenuEvent e) { }

    public void menuCanceled(MenuEvent e) { }

    public void extensionUnloaded() {
        JMenuBar jMenuBar = Utilities.getBurpFrame().getJMenuBar();
        jMenuBar.remove(menuButton);
        jMenuBar.repaint();
    }
}


interface ConfigListener {
    void valueUpdated(String value);
}

class ConfigurableSettings {
    private LinkedHashMap<String, String> settings;
    private NumberFormatter onlyInt;

    private HashMap<String, ConfigListener> callbacks = new HashMap<>();

    public void registerListener(String key, ConfigListener listener) {
        callbacks.put(key, listener);
    }

    void registerSetting(String key, Object value) {
        if (settings.containsKey(key)) {
            return;
        }

        String oldValue = Utilities.callbacks.loadExtensionSetting(key);
        if (oldValue != null) {
            putRaw(key, oldValue);
            return;
        }

        putRaw(key, encode(value));
    }

    ConfigurableSettings() {
        settings = new LinkedHashMap<>();
        put("Add 'fcbz' cachebuster", false);
        put("Add dynamic cachebuster", false);
        put("Add header cachebuster", false);
        put("learn observed words", false);
        put("skip boring words", true);
        put("only report unique params", false);
        put("response", true);
        put("request", true);
        put("use basic wordlist", true);
        put("use bonus wordlist", false);
        put("use custom wordlist", false);
        put("custom wordlist path", "/usr/share/dict/words");
        put("bruteforce", false);
        put("skip uncacheable", false);
        put("dynamic keyload", false);
        put("max one per host", false);
        put("max one per host+status", false);
        put("scan identified params", false);
        put("enable auto-mine", false);
        put("auto-mine headers", false);
        put("auto-mine cookies", false);
        put("auto-mine params", false);
        put("auto-nest params", false);
        put("fuzz detect", false);
        put("carpet bomb", false);
        put("try cache poison", true);
        put("twitchy cache poison", false);
        put("try method flip", false);
        put("try -_ bypass", false);
        put("thread pool size", 8);
        put("rotation interval", 200);
        put("rotation increment", 4);
        put("force bucketsize", -1);
        put("max bucketsize", 65536);
        put("max param length", 32);
        put("lowercase headers", true);
        put("name in issue", false);
        put("canary", "zwrtxqva");

        for(String key: settings.keySet()) {
            //Utilities.callbacks.saveExtensionSetting(key, null); // purge saved settings
            String value = Utilities.callbacks.loadExtensionSetting(key);
            if (Utilities.callbacks.loadExtensionSetting(key) != null) {
                putRaw(key, value);
            }
        }

        NumberFormat format = NumberFormat.getInstance();
        onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(-1);
        onlyInt.setMaximum(Integer.MAX_VALUE);
        onlyInt.setAllowsInvalid(false);

    }

    private ConfigurableSettings(ConfigurableSettings base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    void printSettings() {
        for(String key: settings.keySet()) {
            Utilities.out(key + ": "+settings.get(key));
        }
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        }
        else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        }
        else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
        ConfigListener callback = callbacks.getOrDefault(key, null);
        if (callback != null) {
            callback.valueUpdated(value);
        }
    }

    private void put(String key, Object value) {
        putRaw(key, encode(value));
    }

    String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length()-1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    boolean getBoolean(String key) {
        String val = settings.get(key);
        if ("true".equals(val)) {
            return true;
        }
        else if ("false".equals(val)){
            return false;
        }
        throw new RuntimeException();
    }

    private String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        }
        else if (val.startsWith("\"")) {
            return "string";
        }
        else {
            return "number";
        }
    }

    ConfigurableSettings showSettings() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 4));

        HashMap<String, Object> configured = new HashMap<>();

        for(String key: settings.keySet()) {
            String type = getType(key);
            panel.add(new JLabel("\n"+key+": "));

            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                panel.add(box);
                configured.put(key, box);
            }
            else if (type.equals("number")){
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                panel.add(box);
                configured.put(key, box);
            }
            else {
                JTextField box = new JTextField(getString(key));
                panel.add(box);
                configured.put(key, box);
            }
        }

        int result = JOptionPane.showConfirmDialog(Utilities.getBurpFrame(), panel, "Attack Config", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replaceAll("[^-\\d]", ""));
                }
                else {
                    val = ((JTextField) val).getText();
                }
                put(key, val);
                Utilities.callbacks.saveExtensionSetting(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }



}
