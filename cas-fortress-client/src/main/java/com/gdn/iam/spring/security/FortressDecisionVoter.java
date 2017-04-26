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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.directory.fortress.core.AccessMgr;
import org.apache.directory.fortress.core.AdminMgr;
import org.apache.directory.fortress.core.ReviewMgr;
import org.apache.directory.fortress.core.model.Permission;
import org.apache.directory.fortress.core.model.Session;
import org.apache.directory.fortress.core.rest.AdminMgrRestImpl;
import org.apache.directory.fortress.core.rest.ReviewMgrRestImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class FortressDecisionVoter extends WebExpressionVoter implements InitializingBean {

  private static final Logger LOG = LoggerFactory.getLogger(FortressDecisionVoter.class);
  private static final String IAM_SESSION_ATTRIBUTE_KEY = "iamSession";
  private static final String DEFAULT_ORGANIZATION = "default";
  private static final String IAM_SECURITY_PARAMETER = "IAM_SECURITY_DISABLED";
  private static final long MAXIMUM_CACHE_SIZE = 1000;
  private static final String CATALOG_URL = "catalog";
  private static final String PROFILE_URL = "profile";

  private AccessMgr accessManager;
  private JAXBContext context;
  private String applicationBasePath;
  private String rbacContextId;
  private final Cache<Integer, Session> sessionCache;
  private final Cache<String, Boolean> accessCache;
  private String cacheDuration = "1";
  private final List<String> permissionModels;

  public FortressDecisionVoter() {
    try {
      context = JAXBContext.newInstance(Session.class);
    } catch (JAXBException e) {
      LOG.error("can not creating jaxb context ", e);
    }
    sessionCache = CacheBuilder.newBuilder()
        .expireAfterWrite(Long.valueOf(cacheDuration), TimeUnit.MINUTES)
        .maximumSize(MAXIMUM_CACHE_SIZE).build();
    accessCache = CacheBuilder.newBuilder()
        .expireAfterWrite(Long.valueOf(cacheDuration), TimeUnit.MINUTES)
        .maximumSize(MAXIMUM_CACHE_SIZE).build();
    permissionModels = Arrays.asList(new String[]{CATALOG_URL, PROFILE_URL});
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    AdminMgr adminManager = new AdminMgrRestImpl();
    ReviewMgr reviewManager = new ReviewMgrRestImpl();
    LOG.debug("setting rbac context with value : {}", getRbacContextId());
    adminManager.setContextId(getRbacContextId());
    reviewManager.setContextId(getRbacContextId());
  }

  public AccessMgr getAccessManager() {
    return accessManager;
  }

  public String getApplicationBasePath() {
    return applicationBasePath;
  }

  private String getFilterUrl(HttpServletRequest request) {
    String commonString = null;
    for (String url : permissionModels) {
      LOG.trace("url : {}", url);
      if (commonString == null) {
        LOG.trace("request uri contains url : {}",
            request.getRequestURI().contains(url));
        if (request.getRequestURI().contains(url)) {
          String registeredUrl = getApplicationBasePath() + url;
          LOG.trace("requested url : {}", request.getRequestURL().toString());
          LOG.trace("registered url : {}", registeredUrl);
          commonString = StringUtils
              .getCommonPrefix(new String[] {request.getRequestURL().toString(), registeredUrl});
        }
      }
    }
    return commonString;
  }

  public String getRbacContextId() {
    return rbacContextId;
  }

  public String getSessionCacheDuration() {
    return cacheDuration;
  }

  public void setAccessManager(AccessMgr accessManager) {
    this.accessManager = accessManager;
  }

  public void setApplicationBasePath(String applicationBasePath) {
    this.applicationBasePath = applicationBasePath;
  }

  public void setRbacContextId(String rbacContextId) {
    this.rbacContextId = rbacContextId;
  }

  public void setSessionCacheDuration(String sessionCacheDuration) {
    this.cacheDuration = sessionCacheDuration;
  }

  @Override
  @SuppressWarnings("static-access")
  public int vote(Authentication authentication, FilterInvocation fi,
      Collection<ConfigAttribute> attributes) {
    Authentication securityContextAuthentication =
        SecurityContextHolder.getContext().getAuthentication();
    int result = super.vote(securityContextAuthentication, fi, attributes);
    if (System.getenv(IAM_SECURITY_PARAMETER) != null) {
      LOG.warn("iam security is disable, enable all access mode is enable");
      return result;
    } else {
      LOG.debug("authentication = {}",
          ToStringBuilder.reflectionToString(securityContextAuthentication));
      LOG.debug("super vote for : {}", result);
      if (super.ACCESS_GRANTED == result) {
        String requestMethod = fi.getRequest().getMethod().toLowerCase();
        String filterUrl = getFilterUrl(fi.getHttpRequest());
        if (filterUrl == null) {
          return result;
        }
        try {
          CasAuthenticationToken casAuthenticationToken =
              ((CasAuthenticationToken) securityContextAuthentication);
          LOG.debug("assertion : {}",
              ToStringBuilder.reflectionToString(casAuthenticationToken.getAssertion()));
          String iamSessionXml = (String) casAuthenticationToken.getAssertion().getAttributes()
              .get(IAM_SESSION_ATTRIBUTE_KEY);
          LOG.debug("iam session xml == {}", iamSessionXml);
          Session iamSession = sessionCache.getIfPresent(casAuthenticationToken.getKeyHash());
          if (iamSession == null) {
            Unmarshaller unmarshaller = null;
            try {
              unmarshaller = context.createUnmarshaller();
            } catch (JAXBException ex) {
              LOG.warn("cannot create unmarshaller : ", ex);
            }
            iamSession = (Session) unmarshaller.unmarshal(new StringReader(iamSessionXml));
            sessionCache.put(casAuthenticationToken.getKeyHash(), iamSession);
          }
          StringBuilder sessionPermissionKeyBuilder = new StringBuilder(iamSession.getSessionId()).append(filterUrl).append(requestMethod);
          Boolean isAllowed = accessCache.getIfPresent(sessionPermissionKeyBuilder.toString());
          if(isAllowed == null) {
            isAllowed = accessManager.checkAccess(iamSession, new Permission(filterUrl, requestMethod));
            accessCache.put(sessionPermissionKeyBuilder.toString(), isAllowed);
          }
          LOG.debug("{} is {} to access {} with method {}",
              new Object[] {securityContextAuthentication.getName(),
                  isAllowed ? "granted" : "denied", filterUrl, requestMethod});
          if (isAllowed) {
            return super.ACCESS_GRANTED;
          }
        } catch (Exception e) {
          LOG.error("catch exception when communicate with iam server", e);
        }
      }
      return super.ACCESS_DENIED;
    }
  }
}
