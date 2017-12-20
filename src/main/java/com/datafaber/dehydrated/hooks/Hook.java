package com.datafaber.dehydrated.hooks;

public interface Hook {

  /**
   * prefix to all the challenge record names
   */
  String ACME_CHALLENGE_PREFIX = "_acme-challenge.";


  /**
   * Starts the challenge for the given hostname and record value
   * @param pHostname hostname to create the TXT record for
   * @param pValue value of the TXT record
   * @return true if the record was successfully created at all authoritative nameservers of the domain, false otherwise
   */
  boolean challengeStart (String pHostname, String pValue);


  /**
   * Ends the challenge for the given hostname
   * @param pHostname hostname to delete the TXT record for
   * @return true if the record was successfully deleted at all the authoritative nameservers of the domain, false otherwise
   */
  boolean challengeStop (String pHostname);

}
