---
layout: post
title:  "Cross-Site Request Forgery (CSRF) Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net request forgery csrf
description: Cross-Site Request Forgery (CSRF) Prevention in php, asp.net and java
---
# What is Cross-Site Request Forgery (CSRF) ?

![csrf](/images/csrf.png)

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

### GET scenario


If the application was designed to primarily use GET requests to transfer parameters and execute actions, the money transfer operation might be reduced to a request like:

{% highlight php %}
GET http://bank.com/transfer.do?acct=BOB&amount=100 HTTP/1.1
{% endhighlight %}

Maria now decides to exploit this web application vulnerability using Alice as her victim. Maria first constructs the following exploit URL which will transfer $100,000 from Alice's account to her account. She takes the original command URL and replaces the beneficiary name with herself, raising the transfer amount significantly at the same time:

{% highlight php %}
http://bank.com/transfer.do?acct=MARIA&amount=100000
{% endhighlight %}

The social engineering aspect of the attack tricks Alice into loading this URL when she's logged into the bank application. This is usually done with one of the following techniques:


* sending an unsolicited email with HTML content
* planting an exploit URL or script on pages that are likely to be visited by the victim while they are also doing online banking

The exploit URL can be disguised as an ordinary link, encouraging the victim to click it:

{% highlight php %}
<a href="http://bank.com/transfer.do?acct=MARIA&amount=100000">View my Pictures!</a>
{% endhighlight %}

Or as a 0x0 fake image:

{% highlight php %}
<img src="http://bank.com/transfer.do?acct=MARIA&amount=100000" width="0" height="0" border="0">
{% endhighlight %}

If this image tag were included in the email, Alice wouldn't see anything. However, the browser will still submit the request to bank.com without any visual indication that the transfer has taken place.


A real life example of CSRF attack on an application using GET was a uTorrent exploit from 2008 that was used on a mass scale to download malware


### POST scenario


The only difference between GET and POST attacks is how the attack is being executed by the victim. Let's assume the bank now uses POST and the vulnerable request looks like this:

{% highlight php %}
POST http://bank.com/transfer.do HTTP/1.1

acct=BOB&amount=100
{% endhighlight %}

Such a request cannot be delivered using standard A or IMG tags, but can be delivered using a FORM tag:

{% highlight php %}
<form action="<nowiki>http://bank.com/transfer.do</nowiki>" method="POST">
<input type="hidden" name="acct" value="MARIA"/>
<input type="hidden" name="amount" value="100000"/>
<input type="submit" value="View my pictures"/>
</form>
{% endhighlight %}


# Prevention
 
The most common method to prevent Cross-Site Request Forgery (CSRF) attacks is to append CSRF tokens to each request and associate them with the user’s session. Such tokens should at a minimum be unique per user session, but can also be unique per request. By including a challenge token with each request, the developer can ensure that the request is valid and not coming from a source other than the user.





## PHP

### Example #1


{% highlight php %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" /> 
    <title>PHP CSRF Vulnerable</title>
</head>
<body>
    <form action="index.php" method="post" accept-charset="utf-8">
        <input type="text" name="foo" />
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <input type="submit" value="Submit" />
    </form>
</body>
</html>
{% endhighlight %}

## Solution

### Method #1

{% highlight php %}
<?php
// See: http://blog.ircmaxell.com/2013/02/preventing-csrf-attacks.html
// Start a session (which should use cookies over HTTP only).
session_start();
// Create a new CSRF token.
if (! isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = base64_encode(openssl_random_pseudo_bytes(32));
}
// Check a POST is valid.
if (isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // POST data is valid.
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" /> 
    <title>PHP CSRF Protection</title>

    <script>
    window.csrf = { csrf_token: '<?php echo $_SESSION['csrf_token']; ?>' };
    $.ajaxSetup({
        data: window.csrf
    });
    $(document).ready(function() {
        // CSRF token is now automatically merged in AJAX request data.
        $.post('/awesome/ajax/url', { foo: 'bar' }, function(data) {
            console.log(data);
        });
    });
    </script>
</head>
<body>
    <form action="index.php" method="post" accept-charset="utf-8">
        <input type="text" name="foo" />
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <input type="submit" value="Submit" />
    </form>
</body>
</html>
{% endhighlight %}

## ASP.NET


### Example #1

{% highlight c# %}
<form action="http://example.com/api/account" method="post">
    <input type="hidden" name="Transaction" value="withdraw" />
    <input type="hidden" name="Amount" value="1000000" />
  <input type="submit" value="Click Me"/>
</form>
{% endhighlight %}

## Solutions

### Method #1

{% highlight c# %}
<form action="http://example.com/api/account" method="post">
    @Html.AntiForgeryToken()
    <input type="hidden" name="Transaction" value="withdraw" />
    <input type="hidden" name="Amount" value="1000000" />
  <input type="submit" value="Click Me"/>
</form>
{% endhighlight %}

### Method #2

{% highlight c# %}
using System.Web.Script.Serialization;

public class ExampleClass
{
    public T Deserialize<T>(string str)
    {
        JavaScriptSerializer s = new JavaScriptSerializer();
        return s.Deserialize<T>(str);
    }
}

{% endhighlight %}

## JAVA

### Example #1

index.html

{% highlight java %}
package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.shared.ldap.entry.ModificationOperation;
import org.apache.directory.shared.ldap.entry.client.ClientModification;
import org.apache.directory.shared.ldap.entry.client.DefaultClientAttribute;
import org.apache.directory.shared.ldap.message.ModifyRequestImpl;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.t246osslab.easybuggy.core.dao.EmbeddedADS;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/admins/csrf" })
public class CSRFServlet extends AbstractServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        Locale locale = req.getLocale();

        StringBuilder bodyHtml = new StringBuilder();
        bodyHtml.append("<form action=\"/admins/csrf\" method=\"post\">");
        bodyHtml.append(getMsg("msg.enter.passwd", locale));
        bodyHtml.append("<br><br>");
        bodyHtml.append(getMsg("label.password", locale) + ": ");
        bodyHtml.append("<input type=\"password\" name=\"password\" size=\"30\" maxlength=\"30\" autocomplete=\"off\">");
        bodyHtml.append("<br><br>");
        bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.submit", locale) + "\">");
        bodyHtml.append("<br><br>");
        String errorMessage = (String) req.getAttribute("errorMessage");
        if (errorMessage != null) {
            bodyHtml.append(errorMessage);
        }
        bodyHtml.append(getInfoMsg("msg.note.csrf", locale));
        bodyHtml.append("</form>");
        responseToClient(req, res, getMsg("title.csrf.page", locale), bodyHtml.toString());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        Locale locale = req.getLocale();
        HttpSession session = req.getSession();
        if (session == null) {
            res.sendRedirect("/");
            return;
        }
        String userid = (String) session.getAttribute("userid");
        String password = StringUtils.trim(req.getParameter("password"));
        if (!StringUtils.isBlank(userid) && !StringUtils.isBlank(password) && password.length() >= 8) {
            try {
                DefaultClientAttribute entryAttribute = new DefaultClientAttribute("userPassword", encodeForLDAP(password.trim()));
                ClientModification clientModification = new ClientModification();
                clientModification.setAttribute(entryAttribute);
                clientModification.setOperation(ModificationOperation.REPLACE_ATTRIBUTE);
                ModifyRequestImpl modifyRequest = new ModifyRequestImpl(1);
                modifyRequest.setName(new LdapDN("uid=" + encodeForLDAP(userid.trim()) + ",ou=people,dc=t246osslab,dc=org"));
                modifyRequest.addModification(clientModification);
                EmbeddedADS.getAdminSession().modify(modifyRequest);

                StringBuilder bodyHtml = new StringBuilder();
                bodyHtml.append("<form>");
                bodyHtml.append(getMsg("msg.passwd.changed", locale));
                bodyHtml.append("<br><br>");
                bodyHtml.append("<a href=\"/admins/main\">" + getMsg("label.goto.admin.page", locale) + "</a>");
                bodyHtml.append("</form>");
                responseToClient(req, res, getMsg("title.csrf.page", locale), bodyHtml.toString());
            } catch (Exception e) {
                log.error("Exception occurs: ", e);
                req.setAttribute("errorMessage", getErrMsg("msg.passwd.change.failed", locale));
                doGet(req, res);
            }
        } else {
            if (StringUtils.isBlank(password) || password.length() < 8) {
                req.setAttribute("errorMessage", getErrMsg("msg.passwd.is.too.short", locale));
            } else {
                req.setAttribute("errorMessage", getErrMsg("msg.unknown.exception.occur",
                        new String[] { "userid: " + userid }, locale));
            }
            doGet(req, res);
        }
    }
}
{% endhighlight %}


## Solution

### Method #1

form.html


{% highlight java %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>POC CSRF</title>
    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

    <!-- Optional theme -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
</head>
<body>
        <button type="button" id="requestAction" class="btn btn-lg btn-success">Send request</button>
        <hr class="half-rule"/>
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Requests history</h3>
            </div>
            <div class="panel-body" id="renderingZone"></div>
        </div>


        <!--
        Load custom code after that the DOM loading is fully finished
        See http://stackoverflow.com/a/9899701
        -->
        <script type="text/javascript">
//Variable used to share access to the current CSRF token dictionary
//in which KEY is the backend service name and the VALUE is the current CSRF token to use
var CSRF_TOKENS = {};

//Panel of possible HTTP request type and backend services (used for the demo)
var METHODS_SET = ["GET", "POST", "DELETE", "PUT"];
var BACKEND_SERVICES_SET = ["setUser", "setProfile", "updateAccount", "lockAccount", "initBalance", "resetPassword"];

//Send a random request to a backend service for which a CSRF token is mandatory
function sendRequest(){
    //Select a method
    var methodIndex = Math.floor(Math.random() * ((METHODS_SET.length) - 0)) + 0;
    var method = METHODS_SET[methodIndex];
    //Select a backend service
    var backendServiceIndex = Math.floor(Math.random() * ((BACKEND_SERVICES_SET.length) - 0)) + 0;
    var backendService = BACKEND_SERVICES_SET[backendServiceIndex];
    //Prepare asynchronous Ajax request
    var req = new XMLHttpRequest();
    req.open(method, "/backend/" + backendService + "?param=" + new Date().getTime(), true);
    if(CSRF_TOKENS[backendService] != null){
        req.setRequestHeader("X-TOKEN", CSRF_TOKENS[backendService]);
    }
    req.addEventListener("error", function(evt){ console.error("Request meet an error: " + req.statusText) });
    req.addEventListener("abort", function(evt){ console.error("Request aborted: " + req.statusText) });
    req.addEventListener("load", function(evt){
        if (req.readyState === 4 && req.status === 204) {
            CSRF_TOKENS[backendService] = req.getResponseHeader("X-TOKEN");
            var content = document.getElementById("renderingZone").innerHTML;
            content += "<b>CSRF token initialized for the backend service '" + backendService + "'</b><br>";
            document.getElementById("renderingZone").innerHTML = content;
        }else if (req.readyState === 4 && req.status === 200) {
            CSRF_TOKENS[backendService] = req.getResponseHeader("X-TOKEN");
            var data = JSON.parse(req.responseText);
            var item = "<code>Method: " + data.Method +  " - RequestURI: " + data.RequestURI + " - QueryString: " + data.QueryString + "</code><br>";
            var content = document.getElementById("renderingZone").innerHTML;
            content += item;
            document.getElementById("renderingZone").innerHTML = content;
        }
    });
    //Send request
    req.send(null);
}

//Send a request every 1 sec from 4 scheduler
document.getElementById("requestAction").onclick = sendRequest;
setInterval(sendRequest, 1285);
setInterval(sendRequest, 1456);
setInterval(sendRequest, 1148);
setInterval(sendRequest, 1085);            
</script>
</body>
</html>
{% endhighlight %}


CSRFValidationFilter.java


{% highlight java %}
package eu.righettod.poccsrf.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Filter in charge of validating each incoming HTTP request about Headers and CSRF token.
 * It is called for all requests to backend destination.
 *
 * We use the approach in which:
 * - The CSRF token is changed after each valid HTTP exchange
 * - The custom Header name for the CSRF token transmission is fixed
 * - A CSRF token is associated to a backend service URI in order to enable the support for multiple parallel Ajax request from the same application
 * - The CSRF cookie name is the backend service name prefixed with a fixed prefix
 *
 * Here for the POC we show the "access denied" reason in the response but in production code only return a generic message !!!
 *
 * @see "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet"
 * @see "https://wiki.mozilla.org/Security/Origin"
 * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
 * @see "https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue/"
 */
@WebFilter("/backend/*")
public class CSRFValidationFilter implements Filter {

    /**
     * JVM param name used to define the target origin
     */
    public static final String TARGET_ORIGIN_JVM_PARAM_NAME = "target.origin";

    /**
     * Name of the custom HTTP header used to transmit the CSRF token and also to prefix the CSRF cookie for the expected backend service
     */
    private static final String CSRF_TOKEN_NAME = "X-TOKEN";

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(CSRFValidationFilter.class);

    /**
     * Application expected deployment domain: named "Target Origin" in OWASP CSRF article
     */
    private URL targetOrigin;

    /***
     * Secure generator
     */
    private final SecureRandom secureRandom = new SecureRandom();


    /**
     * {@inheritDoc}
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpResp = (HttpServletResponse) response;
        String accessDeniedReason;

        /* STEP 1: Verifying Same Origin with Standard Headers */
        //Try to get the source from the "Origin" header
        String source = httpReq.getHeader("Origin");
        if (this.isBlank(source)) {
            //If empty then fallback on "Referer" header
            source = httpReq.getHeader("Referer");
            //If this one is empty too then we trace the event and we block the request (recommendation of the article)...
            if (this.isBlank(source)) {
                accessDeniedReason = "CSRFValidationFilter: ORIGIN and REFERER request headers are both absent/empty so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
                return;
            }
        }

        //Compare the source against the expected target origin
        URL sourceURL = new URL(source);
        if (!this.targetOrigin.getProtocol().equals(sourceURL.getProtocol()) || !this.targetOrigin.getHost().equals(sourceURL.getHost()) || this.targetOrigin.getPort() != sourceURL.getPort()) {
            //One the part do not match so we trace the event and we block the request
            accessDeniedReason = String.format("CSRFValidationFilter: Protocol/Host/Port do not fully matches so we block the request! (%s != %s) ", this.targetOrigin, sourceURL);
            LOG.warn(accessDeniedReason);
            httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            return;
        }

        /* STEP 2: Verifying CSRF token using "Double Submit Cookie" approach */
        //If CSRF token cookie is absent from the request then we provide one in response but we stop the process at this stage.
        //Using this way we implement the first providing of token
        Cookie tokenCookie = null;
        if (httpReq.getCookies() != null) {
            String csrfCookieExpectedName = this.determineCookieName(httpReq);
            tokenCookie = Arrays.stream(httpReq.getCookies()).filter(c -> c.getName().equals(csrfCookieExpectedName)).findFirst().orElse(null);
        }
        if (tokenCookie == null || this.isBlank(tokenCookie.getValue())) {
            LOG.info("CSRFValidationFilter: CSRF cookie absent or value is null/empty so we provide one and return an HTTP NO_CONTENT response !");
            //Add the CSRF token cookie and header
            this.addTokenCookieAndHeader(httpReq, httpResp);
            //Set response state to "204 No Content" in order to allow the requester to clearly identify an initial response providing the initial CSRF token
            httpResp.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            //If the cookie is present then we pass to validation phase
            //Get token from the custom HTTP header (part under control of the requester)
            String tokenFromHeader = httpReq.getHeader(CSRF_TOKEN_NAME);
            //If empty then we trace the event and we block the request
            if (this.isBlank(tokenFromHeader)) {
                accessDeniedReason = "CSRFValidationFilter: Token provided via HTTP Header is absent/empty so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            } else if (!tokenFromHeader.equals(tokenCookie.getValue())) {
                //Verify that token from header and one from cookie are the same
                //Here is not the case so we trace the event and we block the request
                accessDeniedReason = "CSRFValidationFilter: Token provided via HTTP Header and via Cookie are not equals so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            } else {
                //Verify that token from header and one from cookie matches
                //Here is the case so we let the request reach the target component (ServiceServlet, jsp...) and add a new token when we get back the bucket
                HttpServletResponseWrapper httpRespWrapper = new HttpServletResponseWrapper(httpResp);
                chain.doFilter(request, httpRespWrapper);
                //Add the CSRF token cookie and header
                this.addTokenCookieAndHeader(httpReq, httpRespWrapper);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        //To easier the configuration, we load the target expected origin from an JVM property
        //Reconfiguration only require an application restart that is generally acceptable
        try {
            this.targetOrigin = new URL(System.getProperty(TARGET_ORIGIN_JVM_PARAM_NAME));
        } catch (MalformedURLException e) {
            LOG.error("Cannot init the filter !", e);
            throw new ServletException(e);
        }
        LOG.info("CSRFValidationFilter: Filter init, set expected target origin to '{}'.", this.targetOrigin);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
        LOG.info("CSRFValidationFilter: Filter shutdown");
    }

    /**
     * Check if a string is null or empty (including containing only spaces)
     *
     * @param s Source string
     * @return TRUE if source string is null or empty (including containing only spaces)
     */
    private boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * Generate a new CSRF token
     *
     * @return The token a string
     */
    private String generateToken() {
        byte[] buffer = new byte[50];
        this.secureRandom.nextBytes(buffer);
        return DatatypeConverter.printHexBinary(buffer);
    }

    /**
     * Determine the name of the CSRF cookie for the targeted backend service
     *
     * @param httpRequest Source HTTP request
     * @return The name of the cookie as a string
     */
    private String determineCookieName(HttpServletRequest httpRequest) {
        String backendServiceName = httpRequest.getRequestURI().replaceAll("/", "-");
        return CSRF_TOKEN_NAME + "-" + backendServiceName;
    }

    /**
     * Add the CSRF token cookie and header to the provided HTTP response object
     *
     * @param httpRequest  Source HTTP request
     * @param httpResponse HTTP response object to update
     */
    private void addTokenCookieAndHeader(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        //Get new token
        String token = this.generateToken();
        //Add cookie manually because the current Cookie class implementation do not support the "SameSite" attribute
        //We let the adding of the "Secure" cookie attribute to the reverse proxy rewriting...
        //Here we lock the cookie from JS access and we use the SameSite new attribute protection
        String cookieSpec = String.format("%s=%s; Path=%s; HttpOnly; SameSite=Strict", this.determineCookieName(httpRequest), token, httpRequest.getRequestURI());
        httpResponse.addHeader("Set-Cookie", cookieSpec);
        //Add cookie header to give access to the token to the JS code
        httpResponse.setHeader(CSRF_TOKEN_NAME, token);
    }
}
{% endhighlight %}
