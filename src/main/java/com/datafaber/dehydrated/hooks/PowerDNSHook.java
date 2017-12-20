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

/**
 * dehydrated hooks using the PowerDNS HTTP API to manipulate records
 *
 * See https://doc.powerdns.com/md/httpapi/README/
 * See https://doc.powerdns.com/md/httpapi/api_spec/
 *
 * How this hook works:
 * for both challenge-start and challenge-end
 *   call /api/v1/servers to get the list of servers
 *   find the id of the authoritative server, if any
 *   get the list of all zones from the server and find the most specific one with respect to our given hostname
 * challengeStart
 *  create the _acme-challenge.hostname TXT record
 *  wait for all the nameservers of the zone to get the newly-created TXT record
 *  exit with a non-zero code if not all nameservers were able to update within the configured timeout
 *  exit with a zero code instead if all nameservers updated within the configured timeout
 * challengeStop
 *  delete the _acme-challenge.hostname TXT record
 *  wait for all the nameservers of the zone to remove the newly-created TXT record
 *  exit with a non-zero code if not all nameservers were able to update within the configured timeout
 *  exit with a zero code instead if all nameservers updated within the configured timeout
 */
public class PowerDNSHook implements Hook {

  // property names specific to this hook
  private static final String PDNS_API_ENDPOINT = "PDNS_API_ENDPOINT";
  private static final String PDNS_API_KEY = "PDNS_API_KEY";
  private static final String DNS_PROPAGATION_WAIT_SECS = "DNS_PROPAGATION_WAIT_SECS";
  private static final String DNS_RESOLUTION_TIMEOUT_SECS = "DNS_RESOLUTION_TIMEOUT_SECS";
  private static final String DNS_RESOLVER = "DNS_RESOLVER";

  private final String mAPIEndpointURL;
  private final String mAPIKey;
  private final String mResolver;
  private final int mPropagationWaitSecs;
  private final int mDnsResolutionTimeoutSecs;

  private static Logger mLogger = LogManager.getLogger("com.datafaber.dehydrated.hooks.PowerDNSHook");


  /**
   * Initializes this hook
   * @param pConfiguration configuration properties
   */
  public PowerDNSHook (Properties pConfiguration) {
    mAPIEndpointURL = pConfiguration.getProperty(PDNS_API_ENDPOINT);
    mAPIKey = pConfiguration.getProperty(PDNS_API_KEY);
    mResolver = pConfiguration.getProperty(DNS_RESOLVER);
    mPropagationWaitSecs = Integer.parseInt(pConfiguration.getProperty(DNS_PROPAGATION_WAIT_SECS));
    mDnsResolutionTimeoutSecs = Integer.parseInt(pConfiguration.getProperty(DNS_RESOLUTION_TIMEOUT_SECS));
  }


  /**
   * Finds the id of the authoritative server at the given endpoint
   * @return server id, or null if not found or errors
   */
  private String findServerId () {
    String ctx = "findServerId - ";
    String id = null;
    String url = "/api/v1/servers";
    try {
      HttpResponse<String> response = Unirest.get(mAPIEndpointURL + url).
              header("Content-Type", "application/json;charset=UTF-8").
              header("X-API-Key", mAPIKey).asString();
      if (!checkResponse(response)) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
        return null;
      }
      String body = response.getBody();
      JSONArray servers = new JSONArray(body);
      if (servers != null && servers.length() > 0) {
        for (int i = 0; i < servers.length(); i++) {
          JSONObject server = servers.getJSONObject(i);
          String daemonType = server.getString("daemon_type");
          if ("authoritative".equals(daemonType)) {
            id = server.getString("id");
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
   * Finds the id of the zone to which the given hostname belongs
   * @param pHostname hostname
   * @param pServerId server id
   * @return zone id, or null if not found or errors
   */
  private String findZoneId (String pHostname, String pServerId) {
    String ctx = "findZoneId - ";
    String id = null;
    String url = "/api/v1/servers/" + pServerId + "/zones";

    // make sure that the hostname ends with a dot or it won't be possible to find the matching zone
    String hostname = pHostname;
    if (!hostname.endsWith(".")) {
      hostname += ".";
    }

    try {
      HttpResponse<String> response = Unirest.get(mAPIEndpointURL + url).
              header("Content-Type", "application/json;charset=UTF-8").
              header("X-API-Key", mAPIKey).
              asString();
      if (!checkResponse(response)) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
        return null;
      }
      String body = response.getBody();
      JSONArray zones = new JSONArray(body);
      String[] hostnameParts = hostname.split("\\.");
      if (zones != null && zones.length() > 0) {
        for (int i = 0; i < zones.length(); i++) {
          JSONObject zone = zones.getJSONObject(i);
          String zoneName = zone.getString("name");
          String[] zoneNameParts = zoneName.split("\\.");
          if (hostnameParts.length == zoneNameParts.length) {
            // certificate for the zone apex, needs an exact match to find the zone
            if (hostname.equals(zoneName)) {
              id = zone.getString("id");
              break;
            }
          } else if (hostnameParts.length > zoneNameParts.length) {
            // certificate for a host in the zone, needs a contains (substring) match only
            String hostnameZone = "";
            for (int j = (hostnameParts.length - zoneNameParts.length); j < hostnameParts.length; j++) {
              hostnameZone += hostnameParts[j] + ".";
            }
            if (hostnameZone.equals(zoneName)) {
              id = zone.getString("id");
              break;
            }
          } else {
            // can happen only if given invalid data
            mLogger.warn(ctx + "could not match hostname " + hostname + " in zone " + zoneName);
          }
        }
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }
    return id;
  }


  /**
   * Sends a request to the PowerDNS API
   * @param pServerId PowerDNS server id (usually "localhost")
   * @param pZoneId id of zone to manipulate
   * @param pRequestBody body of request to send
   * @return true if the response's status code was 200 or 204, false otherwise
   */
  private boolean apiRequest (String pServerId, String pZoneId, JSONObject pRequestBody) {
    String ctx  = "apiRequest - ";
    String url = "/api/v1/servers/" + pServerId + "/zones/" + pZoneId;
    boolean result = false;
    try {
      HttpResponse<String> response = Unirest.patch(mAPIEndpointURL + url).
              header("Content-Type", "application/json;charset=UTF-8").
              header("X-API-Key", mAPIKey).
              body(pRequestBody).
              asString();
      result = checkResponse(response);
      if (!result) {
        mLogger.error(ctx + "API endpoint returned " + response.getStatus() + " for request " + url);
      } else {
        mLogger.info(ctx + "successful API request for request " + url);
      }
    } catch (UnirestException ue) {
      mLogger.error(ctx + "UnirestException for request " + url, ue);
    }
    return result;
  }


  /**
   * Creates the _acme-challenge TXT record for the given hostname in the given zone
   * @param pServerId server id
   * @param pZoneId zone id
   * @param pHostname hostname to create the record for
   * @param pValue value for the TXT record
   * @return true if the challenge record was created, false otherwise
   */
  private boolean createChallengeRecord (String pServerId, String pZoneId, String pHostname, String pValue) {
    // make sure that the hostname ends with a dot or it won't be possible to find the matching zone
    String hostname = pHostname;
    if (!hostname.endsWith(".")) {
      hostname += ".";
    }

    // format for the request body:
    // {
    //    "rrsets": [{
    //              "name": "test.h-lan.net",
    //              "type": "TXT",
    //              "ttl": 30,
    //              "records": [{
    //                "content": "value",
    //                "disabled": false,
    //                "set-ptr": false
    //              }],
    //      "changetype": "REPLACE"
    //    }]
    //  }
    JSONObject record = new JSONObject();
    record.put("content", "\"" + pValue + "\"");
    record.put("disabled", false);
    record.put("set-ptr", false);
    JSONArray records = new JSONArray();
    records.put(record);
    JSONObject rrset = new JSONObject();
    rrset.put("changetype", "REPLACE");
    rrset.put("name", ACME_CHALLENGE_PREFIX + hostname);
    rrset.put("type", "TXT");
    rrset.put("ttl", 30);
    rrset.put("records", records);
    JSONArray rrsets = new JSONArray();
    rrsets.put(rrset);
    JSONObject requestBody = new JSONObject();
    requestBody.put("rrsets", rrsets);
    return apiRequest(pServerId, pZoneId, requestBody);
  }


  /**
   * Deletes the _acme-challenge TXT record for the given hostname in the given zone
   * @param pServerId server id
   * @param pZoneId zone id
   * @param pHostname hostname to create the record for
   * @return true if the challenge record was deleted, false otherwise
   */
  private boolean deleteChallengeRecord (String pServerId, String pZoneId, String pHostname) {
    // make sure that the hostname ends with a dot or it won't be possible to find the matching zone
    String hostname = pHostname;
    if (!hostname.endsWith(".")) {
      hostname += ".";
    }

    JSONObject rrset = new JSONObject();
    rrset.put("changetype", "DELETE");
    rrset.put("name", ACME_CHALLENGE_PREFIX + hostname);
    rrset.put("type", "TXT");
    JSONArray rrsets = new JSONArray();
    rrsets.put(rrset);
    JSONObject requestBody = new JSONObject();
    requestBody.put("rrsets", rrsets);
    return apiRequest(pServerId, pZoneId, requestBody);
  }


  /**
   * Entry point for the challenge-start hook
   * @param pHostname hostname to create the record for
   * @param pValue challenge value
   * @return true if the record was correctly deployed on all authoritative nameservers of the zone, false otherwise
   */
  public boolean challengeStart (String pHostname, String pValue) {
    String ctx = "challengeStart - ";
    mLogger.info(ctx + "starting challenge for " + pHostname + " with value = " + pValue);
    String serverId = findServerId();
    String zoneId = findZoneId(pHostname, serverId);
    boolean recordCreated = createChallengeRecord(serverId, zoneId, pHostname, pValue);
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
    mLogger.info(ctx + "stopping challenge for " + pHostname);
    String serverId = findServerId();
    String zoneId = findZoneId(pHostname, serverId);
    boolean recordDeleted = deleteChallengeRecord(serverId, zoneId, pHostname);
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
   * Checks if the response code allows us to continue
   * @param pResponse http response
   * @return true if the response status is 2xx
   */
  private boolean checkResponse (HttpResponse<?> pResponse) {
    return (pResponse != null)
            && (pResponse.getStatus() == 200 ||
            pResponse.getStatus() == 201 ||
            pResponse.getStatus() == 202 ||
            pResponse.getStatus() == 204);
  }

}
