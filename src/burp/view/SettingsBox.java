package burp.view;

import burp.model.utilities.misc.Utilities;

import java.util.ArrayList;
import java.util.LinkedHashSet;

public class SettingsBox {

public SettingsBox(Utilities utilities) {
  this.utilities = utilities;
}

public void register(String name, Object value) {
  this.register(name, value, null);
}

public void register(String name, Object value, String description) {
  this.settings.add(name);
  utilities.globalSettings.registerSetting(name, value, description);
}

public boolean contains(String key) {
  return this.settings.contains(key);
}

public void importSettings(SettingsBox newSettings) {
  this.settings.addAll(newSettings.getSettings());
}

public ArrayList<String> getSettings() {
  return new ArrayList(this.settings);
}

private final LinkedHashSet<String> settings = new LinkedHashSet<>();
private Utilities             utilities;
}
