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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.model.UserRole;
import org.jasig.cas.client.validation.Assertion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

public class IamUserDetails extends AbstractCasAssertionUserDetailsService {

  private static final String ROLE_USER = "ROLE_USER";
  private static final Logger LOG = LoggerFactory.getLogger(IamUserDetails.class);
  private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";

  private String[] attributes;
  private JAXBContext context;

  public IamUserDetails(String[] attributes) {
    Assert.notNull(attributes, "attributes cannot be null.");
    Assert.isTrue(attributes.length > 0,
        "At least one attribute is required to retrieve roles from.");
    this.attributes = attributes;
    try {
      context = JAXBContext.newInstance(Session.class);
    } catch (JAXBException e) {
      LOG.error("can not creating jaxb unmarshaller", e);
    }
  }

  @Override
  protected UserDetails loadUserDetails(final Assertion assertion) {
    List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    LOG.debug("user asssertion : {}", ToStringBuilder.reflectionToString(assertion));
    boolean accountNonExpired = true;
    boolean credentialsNonExpired = true;
    boolean accountNonLocked = true;
    boolean enabled = true;
    for (String attribute : this.attributes) {
      String value = (String) assertion.getPrincipal().getAttributes().get(attribute);
      LOG.debug("value = {}", value);
      if (value != null) {
        LOG.debug("adding default authorization to user");
        grantedAuthorities.add(new SimpleGrantedAuthority(ROLE_USER));

        Unmarshaller unmarshaller = null;
        Session iamSession = null;
        try {
          unmarshaller = context.createUnmarshaller();
          iamSession = (Session) unmarshaller.unmarshal(new StringReader(value));
          for (UserRole role : iamSession.getRoles()) {
            LOG.debug("adding {} authorization to user", role.getName().toUpperCase());
            grantedAuthorities.add(new SimpleGrantedAuthority(role.getName().toUpperCase()));
          }
        } catch (Exception ex) {
          LOG.error("cannot generate user details", ex);
        }
      }
    }
    LOG.debug(
        "accountNonExpired : {}, credentialsNonExpired : {}, accountNonLocked : {}, enabled : {}",
        new Object[] {accountNonExpired, credentialsNonExpired, accountNonLocked, enabled});
    return new User(assertion.getPrincipal().getName().toLowerCase().trim(), NON_EXISTENT_PASSWORD_VALUE, enabled,
        accountNonExpired, credentialsNonExpired, accountNonLocked, grantedAuthorities);
  }
}
