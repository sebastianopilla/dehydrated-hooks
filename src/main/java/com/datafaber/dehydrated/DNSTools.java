package com.datafaber.dehydrated;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.*;

import java.net.UnknownHostException;
import java.util.Arrays;

public class DNSTools {

  // timeout for single query
  private static final int DNS_TIMEOUT_SECS = 5;

  // max number of tries when polling
  private static final int MAX_POLLING_TRIES = 10;

  private Resolver mResolver;

  private static Logger mLogger = LogManager.getLogger("com.datafaber.dehydrated.DNSTools");


  /**
   * Builds an instance of this class which will use the given hostname as resolver
   * @param pResolverHostname hostname of a resolver
   */
  public DNSTools (String pResolverHostname) {
    try {
      mResolver = new SimpleResolver(pResolverHostname);
    } catch (UnknownHostException uhe) {
      throw new RuntimeException(uhe);
    }
  }


  /**
   * Retrieves the authoritative nameservers of the domain to which the given hostname belongs
   * @param pHostname hostname
   * @return authoritative nameservers for the domain, null if not found
   */
  public String[] findAuthoritativeNameservers (String pHostname) {
    String ctx = "findAuthoritativeNameservers - ";
    if (pHostname == null || "".equals(pHostname)) {
      return null;
    }

    // the given hostname may be a CNAME, for which a "ns" query won't work
    // if that's the case, keep removing subdomains until some nameservers are found
    String hostname = pHostname;
    Record[] nameservers = null;
    while (nameservers == null) {
      try {
        Lookup lookup = new Lookup(hostname, Type.NS);
        lookup.setResolver(mResolver);
        nameservers = lookup.run();
        if (nameservers == null && hostname.contains(".")) {
          hostname = hostname.substring(hostname.indexOf(".") + 1);
        } else {
          break;
        }
      } catch (TextParseException tpe) {
        mLogger.error(ctx + "TextParseException querying for " + hostname, tpe);
      }
    }

    if (nameservers == null) {
      mLogger.warn(ctx + "could not find any authoritative nameserver for " + pHostname);
      return null;
    }

    String[] result = new String[nameservers.length];
    for (int i = 0; i < nameservers.length; i++) {
      result[i] = ((NSRecord)nameservers[i]).getTarget().toString();
    }

    return result;
  }


  /**
   * Polls the given nameservers for the presence of a TXT record having the given value
   * @param pRecordValue value of TXT record
   * @param pNameservers nameservers to poll
   * @param pDnsResolutionTimeoutSecs time we're prepared to wait when one of the nameservers doesn't answer as expected
   * @return true if the record was found in ALL the nameservers, false if at least one nameserver doesn't have the record
   */
  public boolean pollNameserversForChallengeRecordPresence (String pRecordValue, String[] pNameservers, int pDnsResolutionTimeoutSecs) {
    return pollNameserversForChallengeRecord(pRecordValue, pNameservers, pDnsResolutionTimeoutSecs, true);
  }


  /**
   * Polls the given nameservers for the absence of a TXT record having the given value
   * @param pRecordValue value of TXT record
   * @param pNameservers nameservers to poll
   * @param pDnsResolutionTimeoutSecs time we're prepared to wait when one of the nameservers doesn't answer as expected
   * @return true if the record was absent from ALL the nameservers, false if at least one nameserver still has the record
   */
  public boolean pollNameserversForChallengeRecordAbsence (String pRecordValue, String[] pNameservers, int pDnsResolutionTimeoutSecs) {
    return pollNameserversForChallengeRecord(pRecordValue, pNameservers, pDnsResolutionTimeoutSecs, false);
  }


  /**
   * Polls the given nameservers for the presence or absence of a TXT record having the given value
   * @param pRecordValue value of TXT record
   * @param pNameservers nameservers to poll
   * @param pDnsResolutionTimeoutSecs time we're prepared to wait when one of the nameservers doesn't answer as expected
   * @param pCheckPresence true to poll for presence, false to poll for absence
   * @return when polling for presence, true if the record was found in ALL the nameservers, false if at least one nameserver doesn't have the record
   *         when polling for absence, true if the record was absent from ALL the nameservers, false if at least one nameserver still has the record
   */
  private boolean pollNameserversForChallengeRecord (String pRecordValue, String[] pNameservers, int pDnsResolutionTimeoutSecs, boolean pCheckPresence) {
    String ctx = "pollNameserversForChallengeRecord - ";
    if (pRecordValue == null || "".equals(pRecordValue)) {
      return false;
    }
    if (pNameservers == null || pNameservers.length == 0) {
      return false;
    }

    boolean gotAnswer = false;

    try {
      mLogger.info(ctx + "begin polling nameservers for challenge record '" + pRecordValue + "' - nameservers = " + Arrays.toString(pNameservers));
      int cntTries = 1;
      while (!gotAnswer && cntTries <= MAX_POLLING_TRIES) {
        int cntAnswers = 0;
        for (String nameserver : pNameservers) {
          mLogger.info(ctx + "polling nameserver " + nameserver + " - try " + cntTries);
          Record[] records = resolveName(pRecordValue, nameserver);
          if (pCheckPresence) {
            // checking presence, so no result means we have to try again
            if (records == null || records.length == 0) {
              // this nameserver didn't have the answer, so there's no point in querying the others
              // wait for a while, then try again
              mLogger.info(ctx + "answer not found on nameserver " + nameserver);
              waitFor(pDnsResolutionTimeoutSecs);
            } else {
              mLogger.info(ctx + "got expected answer from nameserver " + nameserver);
              cntAnswers++;
            }
          } else {
            // checking absence, so we actually want no result from lookup()
            if (records != null && records.length > 0) {
              mLogger.info(ctx + "answer not found on nameserver " + nameserver);
              waitFor(pDnsResolutionTimeoutSecs);
            } else {
              mLogger.info(ctx + "got expected answer from nameserver " + nameserver);
              cntAnswers++;
            }
          }
        }
        cntTries++;
        gotAnswer = (cntAnswers == pNameservers.length);
      }
      mLogger.info(ctx + "done polling nameservers for challenge record - got answer = " + gotAnswer);
    } catch (UnknownHostException uhe) {
      mLogger.error(ctx + "UnknownHostException while polling for challenge record", uhe);
    } catch (TextParseException tpe) {
      mLogger.error(ctx + "TextParseException while polling for challenge record", tpe);
    }

    return gotAnswer;
  }


  /**
   * Resolves the given name at the given nameserver
   * @param pName name to be resolved
   * @param pNameserver nameserver to use
   * @return records resulting from the lookup or null if not found
   * @throws UnknownHostException if errors
   * @throws TextParseException if errors
   */
  private Record[] resolveName (String pName, String pNameserver) throws UnknownHostException, TextParseException {
    Resolver resolver = new SimpleResolver(pNameserver);
    resolver.setTimeout(DNS_TIMEOUT_SECS);        // set a timeout to avoid waiting forever for a lookup
    Lookup lookup = new Lookup(pName, Type.TXT);
    lookup.setResolver(resolver);
    lookup.setCache(null);                        // no cache for those lookups
    return lookup.run();
  }


  /**
   * Utility method to sleep for the given amount of seconds
   * @param pSecs seconds to sleep for
   */
  private void waitFor (int pSecs) {
    long waitMsecs = pSecs * 1000L;
    try {
      Thread.sleep(waitMsecs);
    } catch (InterruptedException ie) {
      // nothing much that can be done here
    }
  }

}
