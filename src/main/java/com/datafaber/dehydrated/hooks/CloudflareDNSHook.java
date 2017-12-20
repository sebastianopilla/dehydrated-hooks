package com.datafaber.dehydrated.hooks;

import com.datafaber.dehydrated.DNSTools;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Properties;

public class CloudflareDNSHook implements Hook {

  // property names specific to this hook
  private static final String CLOUDFLARE_API_ENDPOINT = "CLOUDFLARE_API_ENDPOINT";
  private static final String CLOUDFLARE_API_EMAIL = "CLOUDFLARE_API_EMAIL";
  private static final String CLOUDFLARE_API_KEY = "CLOUDFLARE_API_KEY";
  private static final String DNS_PROPAGATION_WAIT_SECS = "DNS_PROPAGATION_WAIT_SECS";
  private static final String DNS_RESOLUTION_TIMEOUT_SECS = "DNS_RESOLUTION_TIMEOUT_SECS";
  private static final String DNS_RESOLVER = "DNS_RESOLVER";

  private final String mAPIEndpointURL;
  private final String mAPIEmail;
  private final String mAPIKey;
  private final String mResolver;
  private final int mPropagationWaitSecs;
  private final int mDnsResolutionTimeoutSecs;

  private static Logger mLogger = LogManager.getLogger("com.datafaber.dehydrated.hooks.CloudflareDNSHook");


  /**
   * Initializes this hook
   * @param pConfiguration configuration properties
   */
  public CloudflareDNSHook (Properties pConfiguration) {
    mAPIEndpointURL = pConfiguration.getProperty(CLOUDFLARE_API_ENDPOINT);
    mAPIEmail = pConfiguration.getProperty(CLOUDFLARE_API_EMAIL);
    mAPIKey = pConfiguration.getProperty(CLOUDFLARE_API_KEY);
    mResolver = pConfiguration.getProperty(DNS_RESOLVER);
    mPropagationWaitSecs = Integer.parseInt(pConfiguration.getProperty(DNS_PROPAGATION_WAIT_SECS));
    mDnsResolutionTimeoutSecs = Integer.parseInt(pConfiguration.getProperty(DNS_RESOLUTION_TIMEOUT_SECS));
  }


  /**
   * Finds the id of the zone to which the given hostname belongs
   * @param pHostname hostname
   * @return zone id, or null if not found or errors
   */
  private String findZoneId (String pHostname) {
    String ctx = "findZoneId - ";
    String url = mAPIEndpointURL + "/zones";

    String id = null;
    try {
      // future improvement: handling pagination
      HttpResponse<String> response = Unirest.get(url).
              queryString("status", "active").
              queryString("page", "1").
              queryString("per-page", 50).
              header("X-Auth-Email", mAPIEmail).
              header("X-Auth-Key", mAPIKey).
              header("Content-Type", "application/json;charset=UTF-8").
              asString();
      if (!checkResponse(response)) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
        return null;
      }
      String body = response.getBody();
      JSONObject jsonBody = new JSONObject(body);
      JSONArray zones = jsonBody.getJSONArray("result");
      if (zones != null && zones.length() > 0) {
        for (int i = 0; i < zones.length(); i++) {
          JSONObject zone = zones.getJSONObject(i);
          String zoneName = zone.getString("name");
          if (pHostname.contains(zoneName)) {
            id = zone.getString("id");
            break;
          }
        }
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }

    return id;
  }


  /**
   * Creates the _acme-challenge TXT record for the given hostname in the given zone
   * @param pZoneId zone id
   * @param pHostname hostname to create the record for
   * @param pValue value for the TXT record
   * @return true if the challenge record was created, false otherwise
   */
  private boolean createChallengeRecord (String pZoneId, String pHostname, String pValue) {
    String ctx = "createChallengeRecord - ";

    boolean result = false;

    JSONObject record = new JSONObject();
    record.put("type", "TXT");
    record.put("name", ACME_CHALLENGE_PREFIX + pHostname);
    record.put("content", pValue);
    record.put("ttl", 1);

    String url = mAPIEndpointURL + "/zones/" + pZoneId + "/dns_records";
    try {
      HttpResponse<String> response = Unirest.post(url).
              header("X-Auth-Email", mAPIEmail).
              header("X-Auth-Key", mAPIKey).
              header("Content-Type", "application/json;charset=UTF-8").
              body(record).
              asString();
      result = checkResponse(response);
      if (!result) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }
    return result;
  }


  /**
   * Deletes the _acme-challenge TXT record for the given hostname in the given zone
   * @param pZoneId zone id
   * @param pHostname hostname to create the record for
   */
  private boolean deleteChallengeRecord (String pZoneId, String pHostname) {
    String ctx = "deleteChallengeRecord - ";

    boolean result = false;

    // find the id of the record to delete
    String recordId = null;
    String url = mAPIEndpointURL + "/zones/" + pZoneId + "/dns_records";
    try {
      HttpResponse<String> response = Unirest.get(url).
              queryString("type", "TXT").
              queryString("name", ACME_CHALLENGE_PREFIX + pHostname).
              header("X-Auth-Email", mAPIEmail).
              header("X-Auth-Key", mAPIKey).
              header("Content-Type", "application/json;charset=UTF-8").
              asString();
      result = checkResponse(response);
      if (!result) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
        return result;
      }
      String body = response.getBody();
      JSONObject jsonBody = new JSONObject(body);
      JSONArray jsonResult = jsonBody.getJSONArray("result");
      if (jsonResult.length() > 0) {
        JSONObject record = jsonResult.getJSONObject(0); // only consider the first record in the result
        if (record != null && record.has("id")) {
          recordId = record.getString("id");
        }
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }

    // delete the record
    url = mAPIEndpointURL + "/zones/" + pZoneId + "/dns_records/" + recordId;
    try {
      HttpResponse<String> response = Unirest.delete(url).
              header("X-Auth-Email", mAPIEmail).
              header("X-Auth-Key", mAPIKey).
              header("Content-Type", "application/json;charset=UTF-8").
              asString();
      result = checkResponse(response);
      if (!result) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }
    return result;
  }


  /**
   * Entry point for the challenge-start hook
   * @param pHostname hostname to create the record for
   * @param pValue challenge value
   * @return true if the record was correctly deployed on all authoritative nameservers of the zone, false otherwise
   */
  public boolean challengeStart (String pHostname, String pValue) {
    String ctx = "challengeStart - ";
    String zoneId = findZoneId(pHostname);
    boolean recordCreated = createChallengeRecord(zoneId, pHostname, pValue);
    if (!recordCreated) {
      mLogger.error(ctx + "could not create challenge record for hostname " + pHostname);
      return false;
    }

    DNSTools dnstools = new DNSTools(mResolver);
    String[] nameservers = dnstools.findAuthoritativeNameservers(pHostname);
    if (mLogger.isDebugEnabled()) {
      mLogger.debug(ctx + "found nameservers = " + Arrays.toString(nameservers));
    }

    // wait for a while before polling the nameservers to allow the zone transfers to complete
    mLogger.info(ctx + "waiting " + mPropagationWaitSecs + " seconds for record propagation");
    try {
      Thread.sleep(mPropagationWaitSecs * 1000L);
    } catch (InterruptedException ie) {
      // nothing much to do here
    }

    // poll the authoritative nameservers to find out if the newly created record is actually there
    return dnstools.pollNameserversForChallengeRecordPresence(ACME_CHALLENGE_PREFIX + pHostname, nameservers, mDnsResolutionTimeoutSecs);
  }


  /**
   * Entry point for the challenge-end hook
   * @param pHostname hostname to delete the record for
   * @return true if the record was correctly removed from all authoritative nameservers of the zone, false otherwise
   */
  public boolean challengeStop (String pHostname) {
    String ctx = "challengeStop - ";
    String zoneId = findZoneId(pHostname);
    boolean recordDeleted = deleteChallengeRecord(zoneId, pHostname);
    if (!recordDeleted) {
      mLogger.error(ctx + "could not delete challenge record for hostname " + pHostname);
      return false;
    }

    DNSTools dnstools = new DNSTools(mResolver);
    String[] nameservers = dnstools.findAuthoritativeNameservers(pHostname);
    if (mLogger.isDebugEnabled()) {
      mLogger.debug(ctx + "found nameservers = " + Arrays.toString(nameservers));
    }

    // wait for a while before polling the nameservers to allow the zone transfers to complete
    mLogger.info(ctx + "waiting " + mPropagationWaitSecs + " seconds for record propagation");
    try {
      Thread.sleep(mPropagationWaitSecs * 1000L);
    } catch (InterruptedException ie) {
      // nothing much to do here
    }

    // poll the authoritative nameservers to find out if the newly created record is actually there
    return dnstools.pollNameserversForChallengeRecordAbsence(ACME_CHALLENGE_PREFIX + pHostname, nameservers, mDnsResolutionTimeoutSecs);
  }


  /**
   * Checks if the response code and result allows us to continue
   * @param pResponse http response
   * @return true if the response status is 200 and there is a body with a "result": "success" property
   */
  @SuppressWarnings("unchecked")
  private boolean checkResponse (HttpResponse<?> pResponse) {
    boolean result = false;
    if (pResponse != null
            && pResponse.getStatus() == 200
            && pResponse.getBody() != null) {
      HttpResponse<String> response = (HttpResponse<String>)pResponse;
      JSONObject body = new JSONObject(response.getBody());
      if (body.has("result")) {
        result = Boolean.TRUE.equals(body.getBoolean("success"));
      }
    }
    return result;
  }
}
