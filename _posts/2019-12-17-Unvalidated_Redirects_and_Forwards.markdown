---
layout: post
title:  "Unvalidated Redirects and Forwards Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net request redirect insecure
description: Unvalidated Redirects and Forwards Prevention in php, asp.net and java
---
# What is Unvalidated Redirects and Forwards ?

![Open Redirection](/images/open-redirection-vulnerability.png)

An Open Redirection is when a web application or server uses an unvalidated user-submitted link to redirect the user to a given website or page. Even though it seems like a harmless action to let a user decide to which page he wants to be redirected, such technique if exploited can have a serious impact on the application security, especially when combined with other vulnerabilities and tricks.


When a user clicks on a link of a legitimate website they often won’t be suspicious if suddenly a login prompt shows up. To launch a successful phishing scam, the attacker sends the victim a link, for example via email, which exploits the vulnerability on the vulnerable website example.com:

https://example.com/redirect.php?redirecturl=http://attacker.com/phish/


By exploiting the open redirect vulnerability on the legitimate website using the URL parameter value, the attacker is redirecting the victim to http://attacker.com/phish. This is a phishing page with a trustworthy appearance that is similar to the original site. Once the visitor is on the attacker's malicious website, they enter their credentials on the login form, which points to a script that is controlled by the attacker. The script is typically used to steal user credentials that are being typed in by the victim and save them server-side. Attackers typically use them at a later stage to impersonate the victim on the legitimate web page.


# Prevention
 
The easiest and most effective way to prevent vulnerable open redirects would be to not let the user control where your page redirects them to. If you have to redirect the user based on URLs, instead of using untrusted input you should always use an ID which is internally resolved to the respective URL. If you want the user to be able to issue redirects you should use a redirection page that requires the user to click on the link instead of just redirecting them. You should also check that the URL begins with http:// or https:// and also invalidate all other URLs to prevent the use of malicious URIs such as javascript:



## PHP

### Example #1


{% highlight php %}
<?php
$url = $this->request->getQuery("url");
return $this->redirect($url); // Noncompliant
?>
{% endhighlight %}

## Solution

### Method #1

{% highlight php %}
<?php
$whitelist = array(
  "https://www.sonarsource.com/"
);
$url = $this->request->getQuery("url");
if (in_array($url, $whitelist)) {
  return $this->redirect($url);
} else {
  throw new ForbiddenException();
}
?>
{% endhighlight %}

## ASP.NET


### Example #1

{% highlight c# %}
public class OpenRedirect : Controller
{
  public IActionResult Test(string url)
  {
    return Redirect(url); // Noncompliant
  }
}
{% endhighlight %}

## Solutions

### Method #1

{% highlight c# %}
public class OpenRedirect : Controller
{
  private string[] whiteList = { "https://www.sonarsource.com" };

  public IActionResult Test(string url)
  {
    // Match the incoming URL against a whitelist
    if (!whiteList.Contains(url))
    {
      return BadRequest();
    }

    return Redirect(url);
  }
}
{% endhighlight %}

## JAVA

### Example #1


{% highlight java %}
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String location = req.getParameter("url");
  resp.sendRedirect(location); // Noncompliant
}

{% endhighlight %}


## Solution

### Method #1

{% highlight java %}
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String location = req.getParameter("url");

  // Match the incoming URL against a whitelist
  if (!urlWhiteList.contains(location))
    throw new IOException();

  resp.sendRedirect(location);
}
{% endhighlight %}
