package com.gdn.iam.spring.security;

/*-
 * *
 * cas-fortress-client
 * ==================================
 * Copyright (C) 2017 Blibli.com
 * ==================================
 * Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 * *
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class GdnCasAuthenticationProvider extends CasAuthenticationProvider {

  private static transient Logger LOG = LoggerFactory.getLogger(GdnCasAuthenticationProvider.class);
  private long sleepForDistributeTicketTime = 300;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    try {
      LOG.trace(
          "will try to sleep for waiting ticket to be distributed to other node, sleep time : {}",
          getSleepForDistributeTicketTime());
      Thread.sleep(getSleepForDistributeTicketTime());
    } catch (InterruptedException e) {
      LOG.error("something wrong when sleeping", e);
    }
    return super.authenticate(authentication);
  }

  public long getSleepForDistributeTicketTime() {
    return sleepForDistributeTicketTime;
  }

  public void setSleepForDistributeTicketTime(long sleepForDistributeTicketTime) {
    this.sleepForDistributeTicketTime = sleepForDistributeTicketTime;
  }

}
