//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.view;

import burp.IBurpExtenderCallbacks;
import burp.model.utilities.misc.Utilities;

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

public ConfigurableSettings(HashMap<String, Object> inputSettings, IBurpExtenderCallbacks callbacks) {
  _settings            = new LinkedHashMap<>();
  _defaultSettings     = new LinkedHashMap<>();
  _settingDescriptions = new LinkedHashMap<>();
  _callbacks           = callbacks;
  _listenerHashMap     = new HashMap<>();
  
  Iterator var2 = inputSettings.keySet().iterator();
  
  String key;
  while(var2.hasNext()) {
    key = (String) var2.next();
    this.registerSetting(key, inputSettings.get(key));
  }
  
  var2 = _settings.keySet().iterator();
  
  while(var2.hasNext()) {
    key = (String) var2.next();
    String value = _callbacks.loadExtensionSetting(key);
    if(_callbacks.loadExtensionSetting(key) != null) {
      this.putRaw(key, value);
    }
  }
  
  NumberFormat format = NumberFormat.getInstance();
  this._onlyInt = new NumberFormatter(format);
  this._onlyInt.setValueClass(Integer.class);
  this._onlyInt.setMinimum(-1);
  this._onlyInt.setMaximum(Integer.MAX_VALUE);
  this._onlyInt.setAllowsInvalid(false);
}

public void registerSetting(String key, Object value) {
  this.registerSetting(key, value, null);
}

public void registerSetting(String key, Object value, String description) {
  if(description != null && !description.isEmpty() && !_settingDescriptions.containsKey(key)) {
    _settingDescriptions.put(key, description);
  }
  
  if(!_settings.containsKey(key)) {
    _defaultSettings.put(key, this.encode(value));
    String oldValue = _callbacks.loadExtensionSetting(key);
    if(oldValue != null) {
      this.putRaw(key, oldValue);
    }
    else {
      this.putRaw(key, this.encode(value));
    }
  }
}

private String encode(Object value) {
  String strVal = value.toString().strip();
  if(value instanceof Boolean || "true".equalsIgnoreCase(strVal) || "false".equalsIgnoreCase(strVal)) {
    return String.valueOf(value);
  }
  try {
    Integer.parseInt(strVal);
    return String.valueOf(value);
  }
  catch(NumberFormatException ignored) {
    return "\"" + escapeBackSlashes(strVal) + "\"";
  }
}

private String escapeBackSlashes(String str) {
  return str.replace("\\", "\\\\").replace("\"", "\\\"");
}

private void putRaw(String key, String value) {
  _settings.put(key, value);
  ConfigListener callback = this._listenerHashMap.getOrDefault(key, null);
  if(callback != null) {
    callback.valueUpdated(value);
  }
  
}

public void registerListener(String key, ConfigListener listener) {
  this._listenerHashMap.put(key, listener);
}

public ConfigurableSettings showSettings() {
  return this.showSettings(new ArrayList<>(_settings.keySet()));
}

public ConfigurableSettings showSettings(final ArrayList<String> settingsToShow) {
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
    label.setToolTipText(_settingDescriptions.getOrDefault(key, "No description available"));
    if(!_settings.containsKey(key))
      continue;
    
    if(!_settings.get(key).equals(_defaultSettings.get(key))) {
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
      JTextField box = new JFormattedTextField(this._onlyInt);
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
      // out("Discarding settings...");
      Iterator var2 = settingsToShow.iterator();
      
      while(var2.hasNext()) {
        String key = (String) var2.next();
        _callbacks.saveExtensionSetting(key, null);
      }
      
      ConfigurableSettings.this.setDefaultSettings();
      JComponent comp = (JComponent) e.getSource();
      Window     win  = SwingUtilities.getWindowAncestor(comp);
      win.dispose();
    }
  });
  int result = JOptionPane.showConfirmDialog(Utilities.getBurpFrame(), panel, "Attack Config", 2, -1);
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
      _callbacks.saveExtensionSetting(key, this.encode(val));
    }
    
    return this.createCopy();
  }
  else {
    return null;
  }
}

public void setDefaultSettings() {
  Iterator var1 = _settings.keySet().iterator();
  
  while(var1.hasNext()) {
    String key = (String) var1.next();
    this.putRaw(key, _defaultSettings.get(key));
  }
  
}

private void put(String key, Object value) {
  this.putRaw(key, this.encode(value));
}

public String getString(String key) {
  String decoded = _settings.get(key);
  decoded = decoded.substring(1, decoded.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
  return decoded;
}

public int getInt(String key) {
  return Integer.parseInt(_settings.get(key));
}

public boolean getBoolean(String key) {
  String val = _settings.get(key);
  return "true".equals(val);
}

private String getType(String key) {
  String val = _settings.get(key);
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

private final LinkedHashMap<String, String>   _settings;
private final LinkedHashMap<String, String>   _settingDescriptions;
private final LinkedHashMap<String, String>   _defaultSettings;
private final IBurpExtenderCallbacks          _callbacks;
private final NumberFormatter                 _onlyInt;
private final HashMap<String, ConfigListener> _listenerHashMap;


private ConfigurableSettings createCopy() {
  return new ConfigurableSettings(_settings, _settingDescriptions, _defaultSettings, _callbacks, _onlyInt, _listenerHashMap);
}

public ConfigurableSettings(LinkedHashMap<String, String> settings, LinkedHashMap<String, String> settingDescriptions,
                            LinkedHashMap<String, String> defaultSettings,
                            IBurpExtenderCallbacks callbacks,
                            NumberFormatter onlyInt,
                            HashMap<String, ConfigListener> listenerHashMap
) {
  _settings            = settings;
  _settingDescriptions = settingDescriptions;
  _defaultSettings     = defaultSettings;
  _callbacks           = callbacks;
  _onlyInt             = onlyInt;
  _listenerHashMap     = listenerHashMap;
}

}
