Introduction
============
This document contains an overview of the URL filtering mechanism created by Yudhi Karunia Surtan for PT. Global Digital Niaga (blibli.com).  

I created this solution because at the time i was looking IAM and SSO solution, there are none of the open source solution which can provide the solution that i want to have.  

Basically, the idea is, I want to have a framework where the developer doesn’t need to statically type about the authorization, by using annotation or using "if condition" statement, at their code. With this solution, I’m sure i can have a dynamic authorization mechanism even if the user has been logged in, since the authorization has been centralize at the server then administration can de-assign the user role at runtime environment.  

I searched all the available open source solution and finally i decided to use Apereo CAS and Apache Fortress as the complement solution. Apereo CAS is for the authentication and Apache Fortress is for the authorization. Apereo CAS is very good to handle the Single Sign On and Single Sign Out solution, but in other hand Apereo CAS is lack of the authorization, since there are no standardized solution for the authorization there yet. Apache Fortress is good to authorized, since they are using a standard RBAC. However, Apache Fortress doesn’t have a SSO solution yet there. That is why, I think both can be a good team if they can run together. Unfortunately, there are none of the documentation resource out there to combine both solution. That is why, i need to create this solution to help my developer team life easier.  

With this solution, I successfully put it on the production environment since 2015 and keep maintain this solution until, it has been almost 2 years now, I write this documentation.  

Here the technologies stack used in my extended framework:

1. Apereo CAS  -> 4.2.x  
2. Apache Fortress Enmasse (rest)  -> 1.0.0  
3. Apache Fortress Proxy  -> 1.0.0  
4. Apache Ignite -> 1.7.0  
5. Spring Framework  -> 4.2.x-RELEASE  

There are two type of development that i did, the server side and the client side, which directly used by my team for creating their own web application:  
##### CAS Server side development:   
1. Create own implementation for AbstractUsernamePasswordAuthenticationHandler  
2. Implement Ignite Service Registry for CAS  
##### CAS Client side development:  
1. Create own implementation for WebExpressionVoter  
2. Create own implementation for CasAuthenticationProvider  

Code Descriptions
=================
Server side development:
------------------------
1. The Authentication Handler  
The interesting part for this solution is, how we can maintain both Apereo CAS and Apache Fortress session. Luckily, CAS is using token for maintaining their session and the token is also designed to have some extended attribute to put on it. Using this knowledge, we can do something with the profile given by CAS Server to the client. Let’s have a look what I’ve done with Apereo CAS and Apache Fortress Session in below source code.  

````java
/*
 * Copyright 2017 to PT. Global Digital Niaga(Blibli.com)
 * 
 * Licensed under the Apache License, Version 2.0; you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.gdn.iam.cas;

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
````
at above source code you can see where i construct a new principal by creating new attribute map with value of Apache Fortress Session xml.  

2. Attribute Populator
In order to populate fortress and pass it to the client we need to override **casServiceValidationSuccess.jsp** file, locate at **WEB-INF/view/jsp/protocol/2.0/**, since the default view is not populating the attributes. Here is how i did
```xml
<%@ page session="false" contentType="application/xml; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
	<!-- cas 2 validation success -->
	<cas:authenticationSuccess>
		<cas:user>${fn:escapeXml(assertion.primaryAuthentication.principal.id)}</cas:user>
		<c:if test="${not empty assertion.primaryAuthentication.principal.attributes}">
		<cas:attributes>
			<c:forEach var="attr" items="${assertion.primaryAuthentication.principal.attributes}" >
				<cas:${fn:escapeXml(attr.key)}><![CDATA[${attr.value}]]></cas:${fn:escapeXml(attr.key)}>
			</c:forEach>
		</cas:attributes>
		</c:if>
        <c:if test="${not empty pgtIou}">
        		<cas:proxyGrantingTicket>${pgtIou}</cas:proxyGrantingTicket>
        </c:if>
        <c:if test="${fn:length(assertion.chainedAuthentications) > 1}">
		  <cas:proxies>
            <c:forEach var="proxy" items="${assertion.chainedAuthentications}" varStatus="loopStatus" begin="0" end="${fn:length(assertion.chainedAuthentications)-2}" step="1">
			     <cas:proxy>${fn:escapeXml(proxy.principal.id)}</cas:proxy>
            </c:forEach>
		  </cas:proxies>
        </c:if>
	</cas:authenticationSuccess>
</cas:serviceResponse>
```
One thing that i love from CAS, even you are correctly extract the attribute at this page (or might be you got hacked at this page). CAS Able to protected the returned attribute by changing the services registry configuration. see ***HTTPSandIMAPS-10000001.json*** file. I've put ***ReturnAllAttributeReleasePolicy*** type for debuging all the attribute returning, you can change it later to make your application more secure.

3. Apache Ignite For Ticket Replication    
To have a production readiness we need somehow to have a high availability requirement so we can not have a single cas server. That is why we need to have a centralize or distributed ticket repository so our cas able to scale. To scale the ticket repository, i choose Apache Ignite for distributing the ticket. To Implement is very simple, it is also written at [Apereo CAS documentation](https://apereo.github.io/cas/4.2.x/installation/Ignite-Ticket-Registry.html).

Client side development:
------------------------
1. The Spring Voter  
Spring Framework is a great framework, they allowed you to put your own interceptor to have your own implementation. `WebExpressionVoter` is the class you need to extends in order you want to override the normal spring decision mechanism, usually you will use xml + regex for registering the condition. However, xml + regex is not the approach i want to have for my development team. See below code snippet, to understand what i did for make it more dynamic.  

````java
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
````
Yep, i calling fortress to check if the user is allowed to access fortress permission or not.  

2. UserDetail Populator
Spring use the implementation of AbstractCasAssertionUserDetailsService to populate the user detail after the authentication success, you can see the example at IamUserDetails code, here is the snipet of that class
```java
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
```
you can change the implementation later for your needs.

3. Network Might Give Problem
Since it is the production environment, we need to consider that sometimes it might be a trouble in our network. That is why it is important to give some delay time in our application.
Here is the example how i delay some time in order the network is not as my expectation.  
````java
/*
 * Copyright 2017 to PT. Global Digital Niaga(Blibli.com)
 * 
 * Licensed under the Apache License, Version 2.0; you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.gdn.iam.spring.security;

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

````

Descriptions of authentication flow
===================================
The CAS authentication flow will be the same, there none of changes made in term of the authentication flow. Further, you can see the flow at [Apereo CAS 4.2.x documentation page](https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol.html).  
The main different is we not put the ticket registry inside memory database, we put it on Apache Ignite cache so when other node is there it can replicate the ticket to that node.  

Descriptions of authorization flow
==================================
If you ever use Spring Security, usually you will put the authorization role configuration inside your xml or using annotation. This is the only difference between plain spring security with my extended framework solution, we put the configuration inside Fortress. Everytime user changing the URL, then it will check whenever the user has access to that specific URL or not through the extended voter class. If the user is authorized then the app will give the correct page, otherwise it will give 40X http status and page.

Instructions to test
====================
For testing this example, you need to understand that Apache Fortress configuration is necessary to find fortress.properties at the classpath so it might be good if you put that configuration file at the same classpath, for instance, if you are using tomcat remove all the fortress.properties inside the classes directory and put it on $TOMCAT_HOME/lib/ folder. Make sure you are make Apache Fortress running at the first step. Here are the detail instruction for testing this example :

Server Section
--------------  
1. Read and find the instruction at : 
-- [https://github.com/apache/directory-fortress-core](https://github.com/apache/directory-fortress-core)  
-- [https://github.com/apache/directory-fortress-enmasse](https://github.com/apache/directory-fortress-enmasse)  
-- [https://github.com/apache/directory-fortress-commander](https://github.com/apache/directory-fortress-commander)  
and configure your Apache Fortress properly.
2. Clone the project from link at **Where to download** section below, change the configuration properly inside **cas-fortress-servers/src/main/resources** folder and package it using  
`mvn clean package`.
Copy the war file from **cas-fortress-server/target** into the web-container deploy directory.
3. Start your web-container and you get cas fortress integrated.

Client Section
--------------
1. Simply put the war file inside the web-container deploy directory.
2. Open and login to your commander(fortress-web)
3. Create a user with role `ROLE_USER` (you can change to what ever role). The role need to align with **spring-security.xml** for this statement `<intercept-url pattern="/**" access="hasRole('ROLE_USER')" />`. This is the mandatory role, with this role we are seperate between the anonymous role and authenticate one.
4. Create a permission object containing your restricted url, for instance http://localhost:8080/cas-fortress-client/profile and http://localhost:8080/cas-fortress-client/catalog.
5. Map the permission object and role at permission tab at your commander. Currently we only support get for both of the url.
6. Start your web-container and play with your cas-fortress-client later on.  


Where to download
=================
https://github.com/bliblidotcom/cas-fortress-example

Next Steps
==========
The next step should be implementing ARBAC solution. Since i did not allowed people to create a conditional statement inside their code to check the roles, button or page element that should be not accessible for specific user will appear, even they can not go or do the action, that causing some confusion in term or usability for my user. With ARBAC i believe i can do a whitelist for the page attribute and increase the usability.