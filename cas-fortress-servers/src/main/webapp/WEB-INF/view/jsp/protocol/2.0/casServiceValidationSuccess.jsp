<%@ page session="false" contentType="application/xml; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
	<!-- cas 2 validation success -->
	<!-- debug
	assertion : ${assertion}
	assertion 1 : ${fn:escapeXml(assertion.primaryAuthentication.principal)}
	attribute 1 : ${fn:escapeXml(assertion.primaryAuthentication.principal.attributes)}
	-->
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