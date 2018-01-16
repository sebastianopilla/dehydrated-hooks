package com.datafaber.dehydrated;

import com.datafaber.dehydrated.hooks.CloudflareDNSHook;
import com.datafaber.dehydrated.hooks.Hook;
import com.datafaber.dehydrated.hooks.PowerDNSHook;
import org.apache.commons.cli.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Main entry point
 * <p>
 * Parses the command line arguments and dispatches to the appropriate hook
 */
public class Main {

  // argument names and values
  private static final String CONFIGURATION = "config";
  private static final String COMMAND = "command";
  private static final String COMMAND_DEPLOY_CHALLENGE = "deploy_challenge";
  private static final String COMMAND_CLEAN_CHALLENGE = "clean_challenge";
  private static final Set<String> OTHER_COMMANDS = new HashSet<String>() {
    {
      add("deploy_cert");
      add("unchanged_cert");
      add("invalid_challenge");
      add("request_failure");
      add("startup_hook");
      add("exit_hook");
    }
  };
  private static final String HOSTNAME = "hostname";
  private static final String VALUE = "value";

  // property names and values
  private static final String HOOK_PROPERTY = "HOOK";
  private static final String HOOK_PROPERTY_POWERDNS = "powerdns";
  private static final String HOOK_PROPERTY_CLOUDFLARE = "cloudflare";

  private static Logger mLogger = LogManager.getLogger("com.datafaber.dehydrated.Main");


  /**
   * Main entry point
   * @param pArgs command line arguments
   */
  public static void main (String[] pArgs) {
    // setup parsing of command line arguments
    Options options = buildOptions();
    CommandLineParser parser = new DefaultParser();
    try {
      CommandLine cmd = parser.parse(options, pArgs);
      String command = cmd.getOptionValue(COMMAND);
      String hostname = cmd.getOptionValue(HOSTNAME);
      String value = cmd.getOptionValue(VALUE);
      if (!(COMMAND_DEPLOY_CHALLENGE.equals(command) || COMMAND_CLEAN_CHALLENGE.equals(command))) {
        // exit with status 0 (no errors) if the command is one of OTHER_COMMANDS but not COMMAND_DEPLOY_CHALLENGE nor COMMAND_CLEAN_CHALLENGE
        if (OTHER_COMMANDS.contains(command)) {
          System.exit(0);
        } else {
          // exit with status 42 if we cannot process the command
          System.exit(42);
        }
      }
      String configurationPath = cmd.getOptionValue(CONFIGURATION);
      if (null == configurationPath || "".equals(configurationPath)) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("dnshook", options);
        System.exit(1);
      }
      Properties config = readConfiguration(configurationPath);
      String hookType = config.getProperty(HOOK_PROPERTY);
      Hook hook = null;
      if (HOOK_PROPERTY_POWERDNS.equals(hookType)) {
        hook = new PowerDNSHook(config);
      } else if (HOOK_PROPERTY_CLOUDFLARE.equals(hookType)) {
        hook = new CloudflareDNSHook(config);
      } else {
        // exit with a non-zero status to indicate that the command wasn't accepted
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("dnshook", options);
        System.exit(1);
      }
      if (COMMAND_DEPLOY_CHALLENGE.equals(command)) {
        if (hook.challengeStart(hostname, value)) {
          mLogger.info("Successfully deployed challenge for hostname " + hostname);
          System.exit(0);
        } else {
          mLogger.warn("Could not deploy challenge for hostname " + hostname);
          System.exit(1);
        }
      } else if (COMMAND_CLEAN_CHALLENGE.equals(command)) {
        if (hook.challengeStop(hostname)) {
          mLogger.info("Successfully deleted challenge for hostname " + hostname);
          System.exit(0);
        } else {
          mLogger.warn("Could not delete challenge for hostname " + hostname);
          System.exit(1);
        }
      }
    } catch (ParseException pe) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("dnshook", options);
    }
  }


  /**
   * Reads the specified configuration file
   * @param pConfigurationPath path to the configuration file
   * @return properties read from the configuration
   */
  private static Properties readConfiguration (String pConfigurationPath) {
    String ctx = "readConfiguration - ";
    File configFile = new File(pConfigurationPath);
    if (!configFile.exists()) {
      throw new RuntimeException(ctx + "the specified configuration file " + pConfigurationPath + " does not exist");
    }
    if (!configFile.canRead()) {
      throw new RuntimeException(ctx + "the specified configuration file " + pConfigurationPath + " is not readable");
    }
    Properties config = new Properties();
    try (FileReader reader = new FileReader(configFile)) {
      config.load(reader);
    } catch (FileNotFoundException fnfe) {
      throw new RuntimeException(ctx + "the specified configuration file " + pConfigurationPath + " does not exist");
    } catch (IOException ioe) {
      throw new RuntimeException(ctx + "IOException reading the configuration file " + pConfigurationPath, ioe);
    }
    return config;
  }


  /**
   * Builds the command line option descriptor
   * @return command line options
   */
  private static Options buildOptions () {
    Options options = new Options();
    options.addOption(Option.builder(CONFIGURATION)
            .hasArg()
            .desc("The configuration file specifying the hook type and the hook-specific values, such as API keys")
            .required()
            .build());
    options.addOption(Option.builder(COMMAND)
            .hasArg()
            .desc("The command to execute - challenge-dns-start or challenge-dns-end")
            .required()
            .build());
    options.addOption(Option.builder(HOSTNAME)
            .hasArg()
            .desc("The hostname for which to start or end the challenge")
            .required()
            .build());
    options.addOption(Option.builder(VALUE)
            .hasArg()
            .desc("The text value to set the record to - can be empty")
            .build());
    return options;
  }
}
