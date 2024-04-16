//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package burp.albinowaxUtils;

import burp.IExtensionStateListener;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

public class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener {
private final Utilities utilities;
private JMenu menuButton;
private JMenuItem menuItem;

public ConfigMenu(Utilities utilities) {
  utilities.callbacks.registerExtensionStateListener(this);
  this.utilities = utilities;
}

public void run() {
  try {
    this.menuButton = new JMenu(utilities.name);
    this.menuItem = new JMenuItem(new AbstractAction("Settings") {
      public void actionPerformed(ActionEvent ae) {
        SwingUtilities.invokeLater(new Runnable() {
          public void run() {
            utilities.globalSettings.showSettings();
          }
        });
      }
    });
    this.menuButton.add(this.menuItem);
    JMenuBar burpMenuBar = ConfigurableSettings.getBurpFrame().getJMenuBar();
    burpMenuBar.add(this.menuButton);
    burpMenuBar.repaint();
  } catch (NullPointerException var2) {
    utilities.out("Couldn't find Burp menu bar - probably running headless/enterprise");
  }
  
}

public void menuSelected(MenuEvent e) {
}

public void menuDeselected(MenuEvent e) {
}

public void menuCanceled(MenuEvent e) {
}

public void extensionUnloaded() {
  try {
    JMenuBar jMenuBar = ConfigurableSettings.getBurpFrame().getJMenuBar();
    jMenuBar.remove(this.menuButton);
    jMenuBar.repaint();
  } catch (NullPointerException var2) {
  }
  
}

}
