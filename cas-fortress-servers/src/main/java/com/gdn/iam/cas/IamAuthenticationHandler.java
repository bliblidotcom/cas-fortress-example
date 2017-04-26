package com.gdn.iam.cas;

/*-
 * *
 * cas-fortress-servers
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

import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.apache.directory.fortress.core.AccessMgr;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.model.User;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IamAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

  private static final Logger LOG = LoggerFactory.getLogger(IamAuthenticationHandler.class);
  private AccessMgr accessManager;
  private JAXBContext jaxbContext;
  private Marshaller marshaller;

  public IamAuthenticationHandler() {
    try {
      jaxbContext = JAXBContext.newInstance(Session.class);
      marshaller = jaxbContext.createMarshaller();
    } catch (JAXBException e) {
      LOG.error("cannot bind Session with jaxb context", e);
    }
  }

  @Override
  protected HandlerResult authenticateUsernamePasswordInternal(
      UsernamePasswordCredential usernamePasswordCredential)
          throws GeneralSecurityException, PreventedException {
    String username = usernamePasswordCredential.getUsername();
    String password = usernamePasswordCredential.getPassword();
    Session iamSession = null;
    String iamXmlSession = null;
    try {
      LOG.trace("trying to authenticate username : {}, password : {}",
          new Object[] {username, password});
      iamSession = accessManager.createSession(new User(username, password.toCharArray()), false);
      LOG.trace("iam session : {}", iamSession);
      if (iamSession != null) {
        StringWriter writer = new StringWriter();
        marshaller.marshal(iamSession, writer);
        iamXmlSession = writer.toString();
        LOG.trace("iam xml session : {}", iamXmlSession);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("iamSession", iamXmlSession);
        return createHandlerResult(usernamePasswordCredential,
            principalFactory.createPrincipal(username, attributes), null);
      }
    } catch (org.apache.directory.fortress.core.SecurityException e) {
      String errorMessage = "IAM authentication failed for [" + username + "]";
      LOG.trace(errorMessage);
      throw new GeneralSecurityException(errorMessage);
    } catch (JAXBException e) {
      String errorMessage = "cannot marshalling session with value : " + iamSession == null ? "null"
          : iamSession.toString();
      LOG.trace(errorMessage);
      throw new GeneralSecurityException(errorMessage);
    }
    LOG.trace("returning default handler");
    return createHandlerResult(usernamePasswordCredential,
        principalFactory.createPrincipal(username), null);
  }

  public AccessMgr getAccessManager() {
    return accessManager;
  }

  public void setAccessManager(AccessMgr accessManager) {
    this.accessManager = accessManager;
  }

}
