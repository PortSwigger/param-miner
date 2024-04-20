package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.model.header.HeaderMutationScan;
import burp.model.header.HeaderPoison;
import burp.model.param.OfferParamGuess;
import burp.model.param.ParamGrabber;
import burp.model.scanning.BulkScan;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.FatGetScan;
import burp.model.scanning.GrabScan;
import burp.model.scanning.NormalisedParamScan;
import burp.model.scanning.NormalisedPathScan;
import burp.model.scanning.PortDosScan;
import burp.model.scanning.RailsUtmScan;
import burp.model.scanning.UnkeyedParamScan;
import burp.model.utilities.RandomComparator;
import burp.model.utilities.ResourceLoader;
import burp.model.utilities.Utilities;
import burp.view.ConfigMenu;
import burp.view.SettingsBox;
import org.apache.commons.lang3.StringUtils;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.util.HashMap;
import java.util.Properties;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

///////////////////////////////////////
// CLASS BurpExtender
///////////////////////////////////////
public class BurpExtender implements IBurpExtender, IExtensionStateListener {

// PUBLIC FIELDS
///////////////////////////////////////
public static ParamGrabber paramGrabber;
public static SettingsBox  guessSettings;


// PUBLIC METHODS
///////////////////////////////////////
//-----------------------------------------------------------------------------
@Override
public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
  try {
    configProps = ResourceLoader.loadPropertyFile("ConfigSettings.properties");
    guessProps  = ResourceLoader.loadPropertyFile("GuessSettings.properties");
  }
  catch(IOException e) {
    // This kills the extension since the settings couldn't be loaded
    throw new RuntimeException(e);
  }
  
  utilities      = new Utilities(callbacks, new HashMap<>(), name);
  configSettings = getConfigSettings(utilities);
  guessSettings  = getGuessSettings(utilities);
  
  loadWordlists();
  BlockingQueue<Runnable> tasks;
  if(utilities.globalSettings.getBoolean("enable auto-mine")) {
    tasks = new PriorityBlockingQueue<>(1000, new RandomComparator());
  }
  else {
    tasks = new LinkedBlockingQueue<>();
  }
  
  utilities.globalSettings.registerSetting("thread pool size", 8);
  taskEngine = new ThreadPoolExecutor(utilities.globalSettings.getInt("thread pool size"),
    utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks
  );
  utilities.globalSettings.registerListener("thread pool size", value->{
    utilities.out("Updating active thread pool size to " + value);
    try {
      taskEngine.setCorePoolSize(Integer.parseInt(value));
      taskEngine.setMaximumPoolSize(Integer.parseInt(value));
    }
    catch(IllegalArgumentException e) {
      taskEngine.setMaximumPoolSize(Integer.parseInt(value));
      taskEngine.setCorePoolSize(Integer.parseInt(value));
    }
  });
  
  callbacks.setExtensionName(name);
  
  try {
    StringUtils.isNumeric("1");
  }
  catch(NoClassDefFoundError e) {
    utilities.out(
      "Failed to import the Apache Commons Lang library. You can get it from http://commons.apache" +
        ".org/proper/commons-lang/");
    throw new NoClassDefFoundError();
  }
  
  try {
    callbacks.getHelpers().analyzeResponseVariations();
  }
  catch(NoSuchMethodError e) {
    utilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
    throw new NoSuchMethodError();
  }
  
  paramGrabber = new ParamGrabber(taskEngine, utilities);
  callbacks.registerContextMenuFactory(new OfferParamGuess(callbacks, paramGrabber, taskEngine, utilities));
  
  if(utilities.isBurpPro()) {
    callbacks.registerScannerCheck(new GrabScan(paramGrabber, utilities));
  }
  
  callbacks.registerHttpListener(paramGrabber);
  callbacks.registerProxyListener(paramGrabber);
  
  SwingUtilities.invokeLater(new ConfigMenu(utilities));
  
  BulkScanLauncher launcher = new BulkScanLauncher(BulkScan.scans, utilities);
  
  new HeaderPoison("Header poison", utilities, launcher);
  new PortDosScan("port-DoS", utilities, launcher);
  //new ValueScan("param-value probe");
  new UnkeyedParamScan("Unkeyed param", utilities, launcher);
  new FatGetScan("fat GET", utilities, launcher);
  new NormalisedParamScan("normalised param", utilities, launcher);
  new NormalisedPathScan("normalised path", utilities, launcher);
  new RailsUtmScan("rails param cloaking scan", utilities, launcher);
  new HeaderMutationScan("identify header smuggling mutations", utilities, launcher);
  
  
  utilities.callbacks.registerExtensionStateListener(this);
  
  utilities.out("Loaded " + name + " v" + version);
}  //end registerExtenderCallbacks()


//-----------------------------------------------------------------------------
@Override
public void extensionUnloaded() {
  utilities.log("Aborting all attacks");
  utilities.unloaded.set(true);
  taskEngine.getQueue().clear();
  taskEngine.shutdown();
}


// PRIVATE FIELDS
///////////////////////////////////////
private static final String             name    = "Param Miner";
private static final String             version = "1.4f";

private static final String STATIC_BUSTER_NAME  = "add.static.cache.buster.name";
private static final String STATIC_BUSTER_VALUE = "add.static.cache.buster.value";
private static final String STATIC_BUSTER_DCRPT = "add.static.cache.buster.description";

private static final String DYNAMIC_BUSTER_NAME  = "add.dynamic.cache.buster.name";
private static final String DYNAMIC_BUSTER_VALUE = "add.dynamic.cache.buster.value";
private static final String DYNAMIC_BUSTER_DCRPT = "add.dynamic.cache.buster.description";

private static final String LEARN_WORDS_NAME  = "learn.observed.words.name";
private static final String LEARN_WORDS_VALUE = "learn.observed.words.value";
private static final String LEARN_WORDS_DCRPT = "learn.observed.words.description";

private static final String ENABLE_AUTO_MINE_NAME  = "enable.auto.mine.name";
private static final String ENABLE_AUTO_MINE_VALUE = "enable.auto.mine.value";
private static final String ENABLE_AUTO_MINE_DCRPT = "enable.auto.mine.description";

private static final String MINE_HEADERS_NAME  = "auto.mine.headers.name";
private static final String MINE_HEADERS_VALUE = "auto.mine.headers.value";
private static final String MINE_HEADERS_DCRPT = "auto.mine.headers.description";

private static final String MINE_COOKIES_NAME  = "auto.mine.cookies.name";
private static final String MINE_COOKIES_VALUE = "auto.mine.cookies.value";
private static final String MINE_COOKIES_DCRPT = "auto.mine.cookies.description";

private static final String MINE_PARAMS_NAME  = "auto.mine.params.name";
private static final String MINE_PARAMS_VALUE = "auto.mine.params.value";
private static final String MINE_PARAMS_DCRPT = "auto.mine.params.description";

private static final String NEST_PARAMS_NAME  = "auto.nest.params.name";
private static final String NEST_PARAMS_VALUE = "auto.nest.params.value";
private static final String NEST_PARAMS_DCRPT = "auto.nest.params.description";

private static final String SKIP_BORING_WORDS_NAME = "skip.boring.words.name";
private static final String SKIP_BORING_WORDS_VALUE = "skip.boring.words.value";
private static final String SKIP_BORING_WORDS_DESCRIPTION = "skip.boring.words.description";

private static final String ONLY_REPORT_UNIQUE_PARAMS_NAME = "only.report.unique.params.name";
private static final String ONLY_REPORT_UNIQUE_PARAMS_VALUE = "only.report.unique.params.value";
private static final String ONLY_REPORT_UNIQUE_PARAMS_DESCRIPTION = "only.report.unique.params.description";

private static final String RESPONSE_NAME = "response.name";
private static final String RESPONSE_VALUE = "response.value";
private static final String RESPONSE_DESCRIPTION = "response.description";

private static final String REQUEST_NAME = "request.name";
private static final String REQUEST_VALUE = "request.value";
private static final String REQUEST_DESCRIPTION = "request.description";

private static final String USE_BASIC_WORDLIST_NAME = "use.basic.wordlist.name";
private static final String USE_BASIC_WORDLIST_VALUE = "use.basic.wordlist.value";
private static final String USE_BASIC_WORDLIST_DESCRIPTION = "use.basic.wordlist.description";

private static final String USE_BONUS_WORDLIST_NAME = "use.bonus.wordlist.name";
private static final String USE_BONUS_WORDLIST_VALUE = "use.bonus.wordlist.value";
private static final String USE_BONUS_WORDLIST_DESCRIPTION = "use.bonus.wordlist.description";

private static final String USE_ASSETNOTE_PARAMS_NAME = "use.assetnote.params.name";
private static final String USE_ASSETNOTE_PARAMS_VALUE = "use.assetnote.params.value";
private static final String USE_ASSETNOTE_PARAMS_DESCRIPTION = "use.assetnote.params.description";

private static final String USE_CUSTOM_WORDLIST_NAME = "use.custom.wordlist.name";
private static final String USE_CUSTOM_WORDLIST_VALUE = "use.custom.wordlist.value";
private static final String USE_CUSTOM_WORDLIST_DESCRIPTION = "use.custom.wordlist.description";

private static final String CUSTOM_WORDLIST_PATH_NAME = "custom.wordlist.path.name";
private static final String CUSTOM_WORDLIST_PATH_VALUE = "custom.wordlist.path.value";
private static final String CUSTOM_WORDLIST_PATH_DESCRIPTION = "custom.wordlist.path.description";

private static final String BRUTEFORCE_NAME = "bruteforce.name";
private static final String BRUTEFORCE_VALUE = "bruteforce.value";
private static final String BRUTEFORCE_DESCRIPTION = "bruteforce.description";

private static final String SKIP_UNCACHEABLE_NAME = "skip.uncacheable.name";
private static final String SKIP_UNCACHEABLE_VALUE = "skip.uncacheable.value";
private static final String SKIP_UNCACHEABLE_DESCRIPTION = "skip.uncacheable.description";

private static final String DYNAMIC_KEYLOAD_NAME = "dynamic.keyload.name";
private static final String DYNAMIC_KEYLOAD_VALUE = "dynamic.keyload.value";
private static final String DYNAMIC_KEYLOAD_DESCRIPTION = "dynamic.keyload.description";

private static final String MAX_ONE_PER_HOST_NAME = "max.one.per.host.name";
private static final String MAX_ONE_PER_HOST_VALUE = "max.one.per.host.value";

private static final String MAX_ONE_PER_HOST_STATUS_NAME = "max.one.per.host+status.name";
private static final String MAX_ONE_PER_HOST_STATUS_VALUE = "max.one.per.host+status.value";

private static final String PROBE_IDENTIFIED_PARAMS_NAME = "probe.identified.params.name";
private static final String PROBE_IDENTIFIED_PARAMS_VALUE = "probe.identified.params.value";
private static final String PROBE_IDENTIFIED_PARAMS_DESCRIPTION = "probe.identified.params.description";

private static final String SCAN_IDENTIFIED_PARAMS_NAME = "scan.identified.params.name";
private static final String SCAN_IDENTIFIED_PARAMS_VALUE = "scan.identified.params.value";
private static final String SCAN_IDENTIFIED_PARAMS_DESCRIPTION = "scan.identified.params.description";

private static final String FUZZ_DETECT_NAME = "fuzz.detect.name";
private static final String FUZZ_DETECT_VALUE = "fuzz.detect.value";
private static final String FUZZ_DETECT_DESCRIPTION = "fuzz.detect.description";

private static final String CARPET_BOMB_NAME = "carpet.bomb.name";
private static final String CARPET_BOMB_VALUE = "carpet.bomb.value";
private static final String CARPET_BOMB_DESCRIPTION = "carpet.bomb.description";

private static final String TRY_CACHE_POISON_NAME = "try.cache.poison.name";
private static final String TRY_CACHE_POISON_VALUE = "try.cache.poison.value";
private static final String TRY_CACHE_POISON_DESCRIPTION = "try.cache.poison.description";

private static final String TWITCHY_CACHE_POISON_NAME = "twitchy.cache.poison.name";
private static final String TWITCHY_CACHE_POISON_VALUE = "twitchy.cache.poison.value";
private static final String TWITCHY_CACHE_POISON_DESCRIPTION = "twitchy.cache.poison.description";

private static final String TRY_METHOD_FLIP_NAME = "try.method.flip.name";
private static final String TRY_METHOD_FLIP_VALUE = "try.method.flip.value";
private static final String TRY_METHOD_FLIP_DESCRIPTION = "try.method.flip.description";

private static final String IDENTIFY_SMUGGLE_MUTATIONS_NAME = "identify.smuggle.mutations.name";
private static final String IDENTIFY_SMUGGLE_MUTATIONS_VALUE = "identify.smuggle.mutations.value";
private static final String IDENTIFY_SMUGGLE_MUTATIONS_DESCRIPTION = "identify.smuggle.mutations.description";

private static final String TRY_BYPASS_NAME = "try.bypass.name";
private static final String TRY_BYPASS_VALUE = "try.bypass.value";
private static final String TRY_BYPASS_DESCRIPTION = "try.bypass.description";

private static final String ROTATION_INTERVAL_NAME = "rotation.interval.name";
private static final String ROTATION_INTERVAL_VALUE = "rotation.interval.value";
private static final String ROTATION_INTERVAL_DESCRIPTION = "rotation.interval.description";

private static final String ROTATION_INCREMENT_NAME = "rotation.increment.name";
private static final String ROTATION_INCREMENT_VALUE = "rotation.increment.value";
private static final String ROTATION_INCREMENT_DESCRIPTION = "rotation.increment.description";

private static final String FORCE_BUCKETSIZE_NAME = "force.bucketsize.name";
private static final String FORCE_BUCKETSIZE_VALUE = "force.bucketsize.value";
private static final String FORCE_BUCKETSIZE_DESCRIPTION = "force.bucketsize.description";

private static final String MAX_BUCKETSIZE_NAME = "max.bucketsize.name";
private static final String MAX_BUCKETSIZE_VALUE = "max.bucketsize.value";

private ThreadPoolExecutor taskEngine;
private Properties         configProps;
private Properties         guessProps;
private SettingsBox        configSettings;
private Utilities          utilities;

// PRIVATE METHODS
///////////////////////////////////////
//-----------------------------------------------------------------------------
// currently param-guess displays everything
private SettingsBox getConfigSettings(Utilities utilities) {
  SettingsBox settings = new SettingsBox(utilities);
  register(settings, STATIC_BUSTER_NAME, STATIC_BUSTER_VALUE, STATIC_BUSTER_DCRPT);
  register(settings, DYNAMIC_BUSTER_NAME, DYNAMIC_BUSTER_VALUE, DYNAMIC_BUSTER_DCRPT);
  register(settings, LEARN_WORDS_NAME, LEARN_WORDS_VALUE, LEARN_WORDS_DCRPT);
  register(settings, ENABLE_AUTO_MINE_NAME, ENABLE_AUTO_MINE_VALUE, ENABLE_AUTO_MINE_DCRPT);
  register(settings, MINE_HEADERS_NAME, MINE_HEADERS_VALUE, MINE_HEADERS_DCRPT);
  register(settings, MINE_COOKIES_NAME, MINE_COOKIES_VALUE, MINE_COOKIES_DCRPT);
  register(settings, MINE_PARAMS_NAME, MINE_PARAMS_VALUE, MINE_PARAMS_DCRPT);
  register(settings, NEST_PARAMS_NAME, NEST_PARAMS_VALUE, NEST_PARAMS_DCRPT);
  return settings;
}

//-----------------------------------------------------------------------------
// param-guess only
private SettingsBox getGuessSettings(Utilities utilities) {
  SettingsBox settings = new SettingsBox(utilities);
  register(settings, SKIP_BORING_WORDS_NAME, SKIP_BORING_WORDS_VALUE, SKIP_BORING_WORDS_DESCRIPTION);
  register(settings, ONLY_REPORT_UNIQUE_PARAMS_NAME, ONLY_REPORT_UNIQUE_PARAMS_VALUE, ONLY_REPORT_UNIQUE_PARAMS_DESCRIPTION);
  register(settings, RESPONSE_NAME, RESPONSE_VALUE, RESPONSE_DESCRIPTION);
  register(settings, REQUEST_NAME, REQUEST_VALUE, REQUEST_DESCRIPTION);
  register(settings, USE_BASIC_WORDLIST_NAME, USE_BASIC_WORDLIST_VALUE, USE_BASIC_WORDLIST_DESCRIPTION);
  register(settings, USE_BONUS_WORDLIST_NAME, USE_BONUS_WORDLIST_VALUE, USE_BONUS_WORDLIST_DESCRIPTION);
  register(settings, USE_ASSETNOTE_PARAMS_NAME, USE_ASSETNOTE_PARAMS_VALUE, USE_ASSETNOTE_PARAMS_DESCRIPTION);
  register(settings, USE_CUSTOM_WORDLIST_NAME, USE_CUSTOM_WORDLIST_VALUE, USE_CUSTOM_WORDLIST_DESCRIPTION);
  register(settings, CUSTOM_WORDLIST_PATH_NAME, CUSTOM_WORDLIST_PATH_VALUE, CUSTOM_WORDLIST_PATH_DESCRIPTION);
  register(settings, BRUTEFORCE_NAME, BRUTEFORCE_VALUE, BRUTEFORCE_DESCRIPTION);
  register(settings, SKIP_UNCACHEABLE_NAME, SKIP_UNCACHEABLE_VALUE, SKIP_UNCACHEABLE_DESCRIPTION);
  register(settings, DYNAMIC_KEYLOAD_NAME, DYNAMIC_KEYLOAD_VALUE, DYNAMIC_KEYLOAD_DESCRIPTION);
  register(settings, MAX_ONE_PER_HOST_NAME, MAX_ONE_PER_HOST_VALUE, "");
  register(settings, MAX_ONE_PER_HOST_STATUS_NAME, MAX_ONE_PER_HOST_STATUS_VALUE, "");
  register(settings, PROBE_IDENTIFIED_PARAMS_NAME, PROBE_IDENTIFIED_PARAMS_VALUE, PROBE_IDENTIFIED_PARAMS_DESCRIPTION);
  register(settings, SCAN_IDENTIFIED_PARAMS_NAME, SCAN_IDENTIFIED_PARAMS_VALUE, SCAN_IDENTIFIED_PARAMS_DESCRIPTION);
  register(settings, FUZZ_DETECT_NAME, FUZZ_DETECT_VALUE, FUZZ_DETECT_DESCRIPTION);
  register(settings, CARPET_BOMB_NAME, CARPET_BOMB_VALUE, CARPET_BOMB_DESCRIPTION);
  register(settings, TRY_CACHE_POISON_NAME, TRY_CACHE_POISON_VALUE, TRY_CACHE_POISON_DESCRIPTION);
  register(settings, TWITCHY_CACHE_POISON_NAME, TWITCHY_CACHE_POISON_VALUE, TWITCHY_CACHE_POISON_DESCRIPTION);
  register(settings, TRY_METHOD_FLIP_NAME, TRY_METHOD_FLIP_VALUE, TRY_METHOD_FLIP_DESCRIPTION);
  register(settings, IDENTIFY_SMUGGLE_MUTATIONS_NAME, IDENTIFY_SMUGGLE_MUTATIONS_VALUE, IDENTIFY_SMUGGLE_MUTATIONS_DESCRIPTION);
  register(settings, TRY_BYPASS_NAME, TRY_BYPASS_VALUE, TRY_BYPASS_DESCRIPTION);
  register(settings, ROTATION_INTERVAL_NAME, ROTATION_INTERVAL_VALUE, ROTATION_INTERVAL_DESCRIPTION);
  register(settings, ROTATION_INCREMENT_NAME, ROTATION_INCREMENT_VALUE, ROTATION_INCREMENT_DESCRIPTION);
  register(settings, FORCE_BUCKETSIZE_NAME, FORCE_BUCKETSIZE_VALUE, FORCE_BUCKETSIZE_DESCRIPTION);
  register(settings, MAX_BUCKETSIZE_NAME, MAX_BUCKETSIZE_VALUE, "");
  return settings;
}


//-----------------------------------------------------------------------------
private void register(SettingsBox settings, String name, String value, String description) {
  settings.register(
    configProps.getProperty(name),
    configProps.getProperty(value),
    configProps.getProperty(description)
  );
}


//-----------------------------------------------------------------------------
private void loadWordlists() {
  try(Scanner s = new Scanner(getClass().getResourceAsStream("/functions"))) {
    while(s.hasNext())
      Utilities.phpFunctions.add(s.next());
  }
  
  try(Scanner params = new Scanner(getClass().getResourceAsStream("/params"))) {
    while(params.hasNext())
      Utilities.paramNames.add(params.next());
  }
  
  try(Scanner headers = new Scanner(getClass().getResourceAsStream("/boring_headers"))) {
    while(headers.hasNext())
      Utilities.boringHeaders.add(headers.next().toLowerCase());
  }
} // end loadWordlists()

}
///////////////////////////////////////
// END CLASS BurpExtender
///////////////////////////////////////