package burp;

import burp.model.scanning.mining.HeaderSmugglingMutationScan;
import burp.model.scanning.mining.HeaderPoison;
import burp.model.scanning.guessing.param.OfferParamGuess;
import burp.model.scanning.guessing.param.ParamGrabber;
import burp.model.scanning.BulkScan;
import burp.model.scanning.BulkScanLauncher;
import burp.model.scanning.mining.FatGetScan;
import burp.model.scanning.GrabScan;
import burp.model.scanning.mining.NormalisedParamScan;
import burp.model.scanning.mining.NormalisedPathScan;
import burp.model.scanning.mining.PortDosScan;
import burp.model.scanning.mining.RailsUtmScan;
import burp.model.scanning.mining.UnkeyedParamScan;
import burp.model.utilities.misc.RandomComparator;
import burp.model.utilities.misc.ResourceLoader;
import burp.model.utilities.misc.Utilities;
import burp.view.ConfigMenu;
import burp.view.SettingsBox;

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
public class ParamMiner implements IBurpExtender, IExtensionStateListener {

// PUBLIC METHODS
///////////////////////////////////////
//-----------------------------------------------------------------------------
@Override
public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
  callbacks.setExtensionName(name);
  verifyExtSupported(callbacks);
  configProps    = loadConfigProps();
  utilities      = new Utilities(callbacks, new HashMap<>(), name);
  configSettings = getConfigSettings(utilities);
  guessSettings  = getGuessSettings(utilities);
  loadWordlists();
  setupTaskEngine();
  setupParamGrabber(callbacks);
  SwingUtilities.invokeLater(new ConfigMenu(utilities));
  setupScans();
  utilities.callbacks.registerExtensionStateListener(this);
  utilities.out("Loaded " + name + " v" + version);
}


//-----------------------------------------------------------------------------
@Override
public void extensionUnloaded() {
  utilities.out("Aborting all attacks");
  utilities.unloaded.set(true);
  taskEngine.getQueue().clear();
  taskEngine.shutdown();
}


// PRIVATE FIELDS
///////////////////////////////////////
private static final String name    = "Param Miner";
private static final String version = "1.4f";

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

private static final String THREAD_POOL_NAME  = "thread.pool.name";
private static final String THREAD_POOL_VALUE = "thread.pool.value";
private static final String THREAD_POOL_DCRPT = "thread.pool.description";

private static final String SKIP_BORING_WORDS_NAME        = "skip.boring.words.name";
private static final String SKIP_BORING_WORDS_VALUE       = "skip.boring.words.value";
private static final String SKIP_BORING_WORDS_DSCRPT = "skip.boring.words.description";

private static final String ONLY_REPORT_UNIQUE_PARAMS_NAME        = "only.report.unique.params.name";
private static final String ONLY_REPORT_UNIQUE_PARAMS_VALUE       = "only.report.unique.params.value";
private static final String ONLY_REPORT_UNIQUE_PARAMS_DSCRPT = "only.report.unique.params.description";

private static final String RESPONSE_NAME        = "response.name";
private static final String RESPONSE_VALUE       = "response.value";
private static final String RESPONSE_DSCRPT = "response.description";

private static final String REQUEST_NAME        = "request.name";
private static final String REQUEST_VALUE       = "request.value";
private static final String REQUEST_DSCRPT = "request.description";

private static final String USE_BASIC_WORDLIST_NAME        = "use.basic.wordlist.name";
private static final String USE_BASIC_WORDLIST_VALUE       = "use.basic.wordlist.value";
private static final String USE_BASIC_WORDLIST_DSCRPT = "use.basic.wordlist.description";

private static final String USE_BONUS_WORDLIST_NAME        = "use.bonus.wordlist.name";
private static final String USE_BONUS_WORDLIST_VALUE       = "use.bonus.wordlist.value";
private static final String USE_BONUS_WORDLIST_DSCRPT = "use.bonus.wordlist.description";

private static final String USE_ASSETNOTE_PARAMS_NAME        = "use.assetnote.params.name";
private static final String USE_ASSETNOTE_PARAMS_VALUE       = "use.assetnote.params.value";
private static final String USE_ASSETNOTE_PARAMS_DSCRPT = "use.assetnote.params.description";

private static final String USE_CUSTOM_WORDLIST_NAME        = "use.custom.wordlist.name";
private static final String USE_CUSTOM_WORDLIST_VALUE       = "use.custom.wordlist.value";
private static final String USE_CUSTOM_WORDLIST_DSCRPT = "use.custom.wordlist.description";

private static final String CUSTOM_WORDLIST_PATH_NAME        = "custom.wordlist.path.name";
private static final String CUSTOM_WORDLIST_PATH_VALUE       = "custom.wordlist.path.value";
private static final String CUSTOM_WORDLIST_PATH_DSCRPT = "custom.wordlist.path.description";

private static final String BRUTEFORCE_NAME        = "bruteforce.name";
private static final String BRUTEFORCE_VALUE       = "bruteforce.value";
private static final String BRUTEFORCE_DSCRPT = "bruteforce.description";

private static final String SKIP_UNCACHEABLE_NAME        = "skip.uncacheable.name";
private static final String SKIP_UNCACHEABLE_VALUE       = "skip.uncacheable.value";
private static final String SKIP_UNCACHEABLE_DSCRPT = "skip.uncacheable.description";

private static final String DYNAMIC_KEYLOAD_NAME        = "dynamic.keyload.name";
private static final String DYNAMIC_KEYLOAD_VALUE       = "dynamic.keyload.value";
private static final String DYNAMIC_KEYLOAD_DSCRPT = "dynamic.keyload.description";

private static final String MAX_ONE_PER_HOST_NAME  = "max.one.per.host.name";
private static final String MAX_ONE_PER_HOST_VALUE = "max.one.per.host.value";

private static final String MAX_ONE_PER_HOST_STATUS_NAME  = "max.one.per.host+status.name";
private static final String MAX_ONE_PER_HOST_STATUS_VALUE = "max.one.per.host+status.value";

private static final String PROBE_IDENTIFIED_PARAMS_NAME        = "probe.identified.params.name";
private static final String PROBE_IDENTIFIED_PARAMS_VALUE       = "probe.identified.params.value";
private static final String PROBE_IDENTIFIED_PARAMS_DSCRPT = "probe.identified.params.description";

private static final String SCAN_IDENTIFIED_PARAMS_NAME        = "scan.identified.params.name";
private static final String SCAN_IDENTIFIED_PARAMS_VALUE       = "scan.identified.params.value";
private static final String SCAN_IDENTIFIED_PARAMS_DSCRPT = "scan.identified.params.description";

private static final String FUZZ_DETECT_NAME        = "fuzz.detect.name";
private static final String FUZZ_DETECT_VALUE       = "fuzz.detect.value";
private static final String FUZZ_DETECT_DSCRPT = "fuzz.detect.description";

private static final String CARPET_BOMB_NAME        = "carpet.bomb.name";
private static final String CARPET_BOMB_VALUE       = "carpet.bomb.value";
private static final String CARPET_BOMB_DSCRPT = "carpet.bomb.description";

private static final String TRY_CACHE_POISON_NAME        = "try.cache.poison.name";
private static final String TRY_CACHE_POISON_VALUE       = "try.cache.poison.value";
private static final String TRY_CACHE_POISON_DSCRPT = "try.cache.poison.description";

private static final String TWITCHY_CACHE_POISON_NAME        = "twitchy.cache.poison.name";
private static final String TWITCHY_CACHE_POISON_VALUE       = "twitchy.cache.poison.value";
private static final String TWITCHY_CACHE_POISON_DSCRPT = "twitchy.cache.poison.description";

private static final String TRY_METHOD_FLIP_NAME        = "try.method.flip.name";
private static final String TRY_METHOD_FLIP_VALUE       = "try.method.flip.value";
private static final String TRY_METHOD_FLIP_DSCRPT = "try.method.flip.description";

private static final String IDENTIFY_SMUGGLE_MUTATIONS_NAME        = "identify.smuggle.mutations.name";
private static final String IDENTIFY_SMUGGLE_MUTATIONS_VALUE       = "identify.smuggle.mutations.value";
private static final String IDENTIFY_SMUGGLE_MUTATIONS_DSCRPT = "identify.smuggle.mutations.description";

private static final String TRY_BYPASS_NAME        = "try.bypass.name";
private static final String TRY_BYPASS_VALUE       = "try.bypass.value";
private static final String TRY_BYPASS_DSCRPT = "try.bypass.description";

private static final String ROTATION_INTERVAL_NAME        = "rotation.interval.name";
private static final String ROTATION_INTERVAL_VALUE       = "rotation.interval.value";
private static final String ROTATION_INTERVAL_DSCRPT = "rotation.interval.description";

private static final String ROTATION_INCREMENT_NAME        = "rotation.increment.name";
private static final String ROTATION_INCREMENT_VALUE       = "rotation.increment.value";
private static final String ROTATION_INCREMENT_DSCRPT = "rotation.increment.description";

private static final String FORCE_BUCKETSIZE_NAME   = "force.bucketsize.name";
private static final String FORCE_BUCKETSIZE_VALUE  = "force.bucketsize.value";
private static final String FORCE_BUCKETSIZE_DSCRPT = "force.bucketsize.description";

private static final String MAX_BUCKETSIZE_NAME   = "max.bucketsize.name";
private static final String MAX_BUCKETSIZE_VALUE  = "max.bucketsize.value";
private static final String MAX_BUCKETSIZE_DSCRPT = "max.bucketsize.description";

private static final String MAX_PARAM_LENGTH_NAME   = "max.param.length.name";
private static final String MAX_PARAM_LENGTH_VALUE  = "max.param.length.value";
private static final String MAX_PARAM_LENGTH_DSCRPT = "max.param.length.description";

private static final String LOWERCASE_HEADER_NAME   = "lowercase.headers.name";
private static final String LOWERCASE_HEADER_VALUE  = "lowercase.headers.value";
private static final String LOWERCASE_HEADER_DSCRPT = "lowercase.headers.description";

private static final String NAME_IN_ISSUE_NAME   = "name.in.issue.name";
private static final String NAME_IN_ISSUE_VALUE  = "name.in.issue.value";
private static final String NAME_IN_ISSUE_DSCRPT = "name.in.issue.description";

private static final String CANARY_NAME   = "canary.name";
private static final String CANARY_VALUE  = "canary.value";
private static final String CANARY_DSCRPT = "canary.description";

private static final String FORCE_CANARY_NAME   = "force.canary.name";
private static final String FORCE_CANARY_VALUE  = "force.canary.value";
private static final String FORCE_CANARY_DSCRPT = "force.canary.description";

private static final String POISON_ONLY_NAME   = "poison.only.name";
private static final String POISON_ONLY_VALUE  = "poison.only.value";
private static final String POISON_ONLY_DSCRPT = "poison.only.description";

private static final String TUNNEL_RETRY_NAME   = "tunnelling.retry.count.name";
private static final String TUNNEL_RETRY_VALUE  = "tunnelling.retry.count.value";
private static final String TUNNEL_RETRY_DSCRPT = "tunnelling.retry.count.description";

private static final String ABORT_TUNNEL_FAIL_NAME   = "abort.on.tunnel.failure.name";
private static final String ABORT_TUNNEL_FAIL_VALUE  = "abort.on.tunnel.failure.value";
private static final String ABORT_TUNNEL_FAIL_DSCRPT = "abort.on.tunnel.failure.description";

private ThreadPoolExecutor taskEngine;
private Properties         configProps;
private SettingsBox        configSettings;
private Utilities          utilities;
private BulkScanLauncher   launcher;
private ParamGrabber       paramGrabber;
private SettingsBox        guessSettings;


// PRIVATE METHODS
///////////////////////////////////////
//-----------------------------------------------------------------------------
private void setupTaskEngine() {
  BlockingQueue<Runnable> tasks;
  if(utilities.globalSettings.getBoolean("enable auto-mine"))
    tasks = new PriorityBlockingQueue<>(1000, new RandomComparator());
  else
    tasks = new LinkedBlockingQueue<>();
  
  int threadPool = utilities.globalSettings.getInt("thread pool size");
  taskEngine = new ThreadPoolExecutor(
    threadPool, threadPool, 10, TimeUnit.MINUTES, tasks);
  
  utilities.globalSettings.registerListener("thread pool size", value->{
    utilities.out("Updating active thread pool size to " + value);
    taskEngine.setCorePoolSize(Integer.parseInt(value));
    taskEngine.setMaximumPoolSize(Integer.parseInt(value));
  });
}

//-----------------------------------------------------------------------------
private void setupParamGrabber(IBurpExtenderCallbacks callbacks) {
  paramGrabber = new ParamGrabber(taskEngine, utilities);
  callbacks.registerContextMenuFactory(new OfferParamGuess(paramGrabber, taskEngine, utilities));
  
  if(utilities.isBurpPro()) {
    callbacks.registerScannerCheck(new GrabScan(paramGrabber, utilities));
  }
  
  callbacks.registerHttpListener(paramGrabber);
  callbacks.registerProxyListener(paramGrabber);
}


//-----------------------------------------------------------------------------
private void verifyExtSupported(IBurpExtenderCallbacks callbacks) {
  try {
    callbacks.getHelpers().analyzeResponseVariations();
  }
  catch(NoSuchMethodError e) {
    utilities.out("This extension requires Burp Suite Pro 1.7.10 or later");
    throw new NoSuchMethodError();
  }
}

//-----------------------------------------------------------------------------
private Properties loadConfigProps() {
  try {
    return ResourceLoader.loadPropertyFile("ConfigSettings.properties");
  }
  catch(IOException e) {
    // This kills the extension since the settings couldn't be loaded
    throw new RuntimeException(e);
  }
}

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
  register(settings, THREAD_POOL_NAME, THREAD_POOL_VALUE, THREAD_POOL_DCRPT);
  return settings;
}

//-----------------------------------------------------------------------------
// param-guess only
private SettingsBox getGuessSettings(Utilities utilities) {
  SettingsBox settings = new SettingsBox(utilities);
  register(settings, SKIP_BORING_WORDS_NAME, SKIP_BORING_WORDS_VALUE, SKIP_BORING_WORDS_DSCRPT);
  register(settings, ONLY_REPORT_UNIQUE_PARAMS_NAME, ONLY_REPORT_UNIQUE_PARAMS_VALUE, ONLY_REPORT_UNIQUE_PARAMS_DSCRPT);
  register(settings, RESPONSE_NAME, RESPONSE_VALUE, RESPONSE_DSCRPT);
  register(settings, REQUEST_NAME, REQUEST_VALUE, REQUEST_DSCRPT);
  register(settings, USE_BASIC_WORDLIST_NAME, USE_BASIC_WORDLIST_VALUE, USE_BASIC_WORDLIST_DSCRPT);
  register(settings, USE_BONUS_WORDLIST_NAME, USE_BONUS_WORDLIST_VALUE, USE_BONUS_WORDLIST_DSCRPT);
  register(settings, USE_ASSETNOTE_PARAMS_NAME, USE_ASSETNOTE_PARAMS_VALUE, USE_ASSETNOTE_PARAMS_DSCRPT);
  register(settings, USE_CUSTOM_WORDLIST_NAME, USE_CUSTOM_WORDLIST_VALUE, USE_CUSTOM_WORDLIST_DSCRPT);
  register(settings, CUSTOM_WORDLIST_PATH_NAME, CUSTOM_WORDLIST_PATH_VALUE, CUSTOM_WORDLIST_PATH_DSCRPT);
  register(settings, BRUTEFORCE_NAME, BRUTEFORCE_VALUE, BRUTEFORCE_DSCRPT);
  register(settings, SKIP_UNCACHEABLE_NAME, SKIP_UNCACHEABLE_VALUE, SKIP_UNCACHEABLE_DSCRPT);
  register(settings, DYNAMIC_KEYLOAD_NAME, DYNAMIC_KEYLOAD_VALUE, DYNAMIC_KEYLOAD_DSCRPT);
  register(settings, MAX_ONE_PER_HOST_NAME, MAX_ONE_PER_HOST_VALUE, "");
  register(settings, MAX_ONE_PER_HOST_STATUS_NAME, MAX_ONE_PER_HOST_STATUS_VALUE, "");
  register(settings, PROBE_IDENTIFIED_PARAMS_NAME, PROBE_IDENTIFIED_PARAMS_VALUE, PROBE_IDENTIFIED_PARAMS_DSCRPT);
  register(settings, SCAN_IDENTIFIED_PARAMS_NAME, SCAN_IDENTIFIED_PARAMS_VALUE, SCAN_IDENTIFIED_PARAMS_DSCRPT);
  register(settings, FUZZ_DETECT_NAME, FUZZ_DETECT_VALUE, FUZZ_DETECT_DSCRPT);
  register(settings, CARPET_BOMB_NAME, CARPET_BOMB_VALUE, CARPET_BOMB_DSCRPT);
  register(settings, TRY_CACHE_POISON_NAME, TRY_CACHE_POISON_VALUE, TRY_CACHE_POISON_DSCRPT);
  register(settings, TWITCHY_CACHE_POISON_NAME, TWITCHY_CACHE_POISON_VALUE, TWITCHY_CACHE_POISON_DSCRPT);
  register(settings, TRY_METHOD_FLIP_NAME, TRY_METHOD_FLIP_VALUE, TRY_METHOD_FLIP_DSCRPT);
  register(settings, IDENTIFY_SMUGGLE_MUTATIONS_NAME, IDENTIFY_SMUGGLE_MUTATIONS_VALUE, IDENTIFY_SMUGGLE_MUTATIONS_DSCRPT);
  register(settings, TRY_BYPASS_NAME, TRY_BYPASS_VALUE, TRY_BYPASS_DSCRPT);
  register(settings, ROTATION_INTERVAL_NAME, ROTATION_INTERVAL_VALUE, ROTATION_INTERVAL_DSCRPT);
  register(settings, ROTATION_INCREMENT_NAME, ROTATION_INCREMENT_VALUE, ROTATION_INCREMENT_DSCRPT);
  register(settings, FORCE_BUCKETSIZE_NAME, FORCE_BUCKETSIZE_VALUE, FORCE_BUCKETSIZE_DSCRPT);
  register(settings, MAX_BUCKETSIZE_NAME, MAX_BUCKETSIZE_VALUE, MAX_BUCKETSIZE_DSCRPT);
  register(settings, MAX_PARAM_LENGTH_NAME, MAX_PARAM_LENGTH_VALUE, MAX_PARAM_LENGTH_DSCRPT);
  register(settings, LOWERCASE_HEADER_NAME, LOWERCASE_HEADER_VALUE, LOWERCASE_HEADER_DSCRPT);
  register(settings, NAME_IN_ISSUE_NAME, NAME_IN_ISSUE_VALUE, NAME_IN_ISSUE_DSCRPT);
  register(settings, CANARY_NAME, CANARY_VALUE, CANARY_DSCRPT);
  register(settings, FORCE_CANARY_NAME, FORCE_CANARY_VALUE, FORCE_CANARY_DSCRPT);
  register(settings, POISON_ONLY_NAME, POISON_ONLY_VALUE, POISON_ONLY_DSCRPT);
  register(settings, TUNNEL_RETRY_NAME, TUNNEL_RETRY_VALUE, TUNNEL_RETRY_DSCRPT);
  register(settings, ABORT_TUNNEL_FAIL_NAME, ABORT_TUNNEL_FAIL_VALUE, ABORT_TUNNEL_FAIL_DSCRPT);
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

//-----------------------------------------------------------------------------
private void setupScans() {
  launcher = new BulkScanLauncher(BulkScan.scans, utilities);
  new HeaderPoison("Header poison", utilities, launcher, guessSettings, paramGrabber);
  new PortDosScan("port-DoS", utilities, launcher);
  //new ValueScan("param-value probe");
  new UnkeyedParamScan("Unkeyed param", utilities, launcher);
  new FatGetScan("fat GET", utilities, launcher);
  new NormalisedParamScan("normalised param", utilities, launcher);
  new NormalisedPathScan("normalised path", utilities, launcher);
  new RailsUtmScan("rails param cloaking scan", utilities, launcher);
  new HeaderSmugglingMutationScan("identify header smuggling mutations", utilities, launcher);
}

}
///////////////////////////////////////
// END CLASS BurpExtender
///////////////////////////////////////