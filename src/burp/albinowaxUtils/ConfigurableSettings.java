//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.Utilities;

import java.awt.Color;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.text.NumberFormatter;

public class ConfigurableSettings {
public ConfigurableSettings(HashMap<String, Object> inputSettings, Utilities utilities) {
  this.utilities = utilities;
  Iterator var2 = inputSettings.keySet().iterator();
  
  String key;
  while(var2.hasNext()) {
    key = (String) var2.next();
    this.registerSetting(key, inputSettings.get(key));
  }
  
  var2 = settings.keySet().iterator();
  
  while(var2.hasNext()) {
    key = (String) var2.next();
    String value = utilities.callbacks.loadExtensionSetting(key);
    if(utilities.callbacks.loadExtensionSetting(key) != null) {
      this.putRaw(key, value);
    }
  }
  
  NumberFormat format = NumberFormat.getInstance();
  this.onlyInt = new NumberFormatter(format);
  this.onlyInt.setValueClass(Integer.class);
  this.onlyInt.setMinimum(-1);
  this.onlyInt.setMaximum(Integer.MAX_VALUE);
  this.onlyInt.setAllowsInvalid(false);
}

public void registerSetting(String key, Object value) {
  this.registerSetting(key, value, null);
}

public void registerSetting(String key, Object value, String description) {
  if(description != null && !settingDescriptions.containsKey(key)) {
    settingDescriptions.put(key, description);
  }
  
  if(!settings.containsKey(key)) {
    defaultSettings.put(key, this.encode(value));
    String oldValue = utilities.callbacks.loadExtensionSetting(key);
    if(oldValue != null) {
      this.putRaw(key, oldValue);
    }
    else {
      this.putRaw(key, this.encode(value));
    }
  }
}

private String encode(Object value) {
  String encoded;
  if(value instanceof Boolean) {
    encoded = String.valueOf(value);
  }
  else if(value instanceof Integer) {
    encoded = String.valueOf(value);
  }
  else {
    encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }
  
  return encoded;
}

private void putRaw(String key, String value) {
  settings.put(key, value);
  ConfigListener callback = this.callbacks.getOrDefault(key, null);
  if(callback != null) {
    callback.valueUpdated(value);
  }
  
}

public void registerListener(String key, ConfigListener listener) {
  this.callbacks.put(key, listener);
}

public void printSettings() {
  Iterator var1 = settings.keySet().iterator();
  
  while(var1.hasNext()) {
    String key = (String) var1.next();
    utilities.out(key + ": " + settings.get(key));
  }
  
}

public ConfigurableSettings showSettings() {
  return this.showSettings(new ArrayList<>(settings.keySet()));
}

ConfigurableSettings showSettings(final ArrayList<String> settingsToShow) {
  JPanel panel = new JPanel();
  panel.setLayout(new GridLayout(0, 6));
  panel.setSize(800, 800);
  HashMap<String, Object> configured          = new HashMap();
  JButton                 buttonResetSettings = new JButton("Reset Visible Settings");
  Iterator                var5                = settingsToShow.iterator();
  
  String key;
  while(var5.hasNext()) {
    key = (String) var5.next();
    String keyType = this.getType(key);
    JLabel label = new JLabel("\n" + key + ": ");
    label.setToolTipText(settingDescriptions.getOrDefault(key, "No description available"));
    if(!settings.containsKey(key))
      continue;
    
    if(!settings.get(key).equals(defaultSettings.get(key))) {
      label.setForeground(Color.magenta);
    }
    
    panel.add(label);
    if(keyType.equals("boolean")) {
      JCheckBox box = new JCheckBox();
      box.setSelected(this.getBoolean(key));
      panel.add(box);
      configured.put(key, box);
    }
    else if(keyType.equals("number")) {
      JTextField box = new JFormattedTextField(this.onlyInt);
      box.setText(String.valueOf(this.getInt(key)));
      panel.add(box);
      configured.put(key, box);
    }
    else {
      String     value = this.getString(key);
      JTextField box   = new JTextField(value, value.length());
      box.setColumns(1);
      panel.add(box);
      configured.put(key, box);
    }
  }
  
  panel.add(new JLabel(""));
  panel.add(new JLabel(""));
  panel.add(buttonResetSettings);
  buttonResetSettings.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
      utilities.out("Discarding settings...");
      Iterator var2 = settingsToShow.iterator();
      
      while(var2.hasNext()) {
        String key = (String) var2.next();
        utilities.callbacks.saveExtensionSetting(key, null);
      }
      
      ConfigurableSettings.this.setDefaultSettings();
      JComponent comp = (JComponent) e.getSource();
      Window     win  = SwingUtilities.getWindowAncestor(comp);
      win.dispose();
    }
  });
  int result = JOptionPane.showConfirmDialog(utilities.getBurpFrame(), panel, "Attack Config", 2, -1);
  if(result == 0) {
    Iterator var12 = configured.keySet().iterator();
    
    while(var12.hasNext()) {
      key = (String) var12.next();
      Object val = configured.get(key);
      if(val instanceof JCheckBox) {
        val = ((JCheckBox) val).isSelected();
      }
      else if(val instanceof JFormattedTextField) {
        val = Integer.parseInt(((JFormattedTextField) val).getText().replaceAll("[^-\\d]", ""));
      }
      else {
        val = ((JTextField) val).getText();
      }
      
      this.put(key, val);
      utilities.callbacks.saveExtensionSetting(key, this.encode(val));
    }
    
    return new ConfigurableSettings(utilities, this);
  }
  else {
    return null;
  }
}

public void setDefaultSettings() {
  Iterator var1 = settings.keySet().iterator();
  
  while(var1.hasNext()) {
    String key = (String) var1.next();
    this.putRaw(key, defaultSettings.get(key));
  }
  
}

private void put(String key, Object value) {
  this.putRaw(key, this.encode(value));
}

public String getString(String key) {
  String decoded = settings.get(key);
  decoded = decoded.substring(1, decoded.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
  return decoded;
}

public int getInt(String key) {
  return Integer.parseInt(settings.get(key));
}

public boolean getBoolean(String key) {
  String val = settings.get(key);
  return "true".equals(val);
}

private String getType(String key) {
  String val = settings.get(key);
  if(!val.equals("true") && !val.equals("false")) {
    return val.startsWith("\"") ? "string" : "number";
  }
  else {
    return "boolean";
  }
}

static JFrame getBurpFrame() {
  Frame[] var0 = Frame.getFrames();
  int     var1 = var0.length;
  
  for(int var2 = 0; var2 < var1; ++var2) {
    Frame f = var0[var2];
    if(f.isVisible() && f.getTitle().startsWith("Burp Suite")) {
      return (JFrame) f;
    }
  }
  
  return null;
}
private static final LinkedHashMap<String, String> settings            = new LinkedHashMap<>();
private static final LinkedHashMap<String, String> settingDescriptions = new LinkedHashMap<>();
private static final LinkedHashMap<String, String> defaultSettings     = new LinkedHashMap<>();
private final        burp.Utilities                utilities;
private final NumberFormatter                 onlyInt;
private final HashMap<String, ConfigListener> callbacks = new HashMap();

private ConfigurableSettings(burp.Utilities utilities, ConfigurableSettings base) {
  this.utilities = utilities;
  this.onlyInt   = base.onlyInt;
}
}
