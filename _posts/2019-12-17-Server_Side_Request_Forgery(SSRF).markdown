---
layout: post
title:  "Server Side Request Forgery (SSRF) Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net request forgery ssrf
description: Server Side Request Forgery (SSRF) Prevention in php, asp.net and java
---
# What is Server Side Request Forgery (SSRF) ?

![ssrf](/images/ssrf.png)

Server Side Request Forgery (SSRF) vulnerabilities let an attacker send crafted requests from the back-end server of a vulnerable web application. Criminals usually use SSRF attacks to target internal systems that are behind firewalls and are not accessible from the external network. An attacker may also leverage SSRF to access services available through the loopback interface (127.0.0.1) of the exploited server.


SSRF vulnerabilities occur when an attacker has full or partial control of the request sent by the web application. A common example is when an attacker can control the third-party service URL to which the web application makes a request.


# Prevention
 
To prevent SSRF vulnerabilities in your web applications it is strongly advised to use a whitelist of allowed domains and protocols from where the web server can fetch remote resources.

Also, as a rule of thumb you should avoid using user input directly in functions that can make requests on behalf of the server. You should also sanitize and filter user input, but it is typically very hard to implement mainly because it is virtually impossible to cover all the different scenarios.


The problem could be mitigated in any of the following ways:


- Validate the user provided data based on a whitelist and reject input not matching.
- Redesign the application to not send requests based on user provided data.



## PHP

### Example #1


{% highlight php %}
<?php
$filename = strip_tags($_GET['url']);

if (substr($filename,0,4) !== 'http') {
    die("Need a valid URL...");
}

$ext = pathinfo($filename, PATHINFO_EXTENSION);


switch ($ext) {
    case "gif":
        header('Content-Type: image/gif');
        readfile($filename);
        break;
    case "png":
        header('Content-Type: image/png');
        readfile($filename);
        break;
    case "jpg":
    default:
        header('Content-Type: image/jpeg');
        readfile($filename);
        break;
}
?>
{% endhighlight %}

## Solution

### Method #1

{% highlight php %}
<?php

$whitelist = [
    'some.whitelisted.com',
    'other.whitelisted.com'
];

$extensionMap = [
    'gif'  => 'image/gif',
    'png'  => 'image/png',
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg'
];

$filename = strip_tags($_GET['url']);

$host = parse_url($filename, PHP_URL_HOST);

if(empty($host) || !in_array($host, $whitelist)) {
    header('HTTP/1.1 404 Not Found');
    exit;
}

$ext = pathinfo($filename, PATHINFO_EXTENSION);

if(!isset($extensionMap[$ext])) {
    header('HTTP/1.1 404 Not Found');
    exit;
}

header(sprintf('Content-Type: %s', $extensionMap[$ext]));
readfile($filename);
{% endhighlight %}

## ASP.NET


### Example #1

{% highlight c# %}
public class SSRF : Controller
{
  public IActionResult Test(string url)
  {
    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url); // Noncompliant
    // ...
  }
}
{% endhighlight %}

## Solutions

### Method #1

{% highlight c# %}
public class SSRF : Controller
{
  private string[] whiteList = { "https://www.sonarsource.com" };

  public IActionResult Test(string url)
  {
    // Match the incoming URL against a whitelist
    if (!whiteList.Contains(url))
    {
      return BadRequest();
    }

    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
    // ...
  }
}
{% endhighlight %}

## JAVA

### Example #1


{% highlight java %}
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  URL url = new URL(req.getParameter("url"));
  HttpURLConnection conn = (HttpURLConnection) url.openConnection(); // Noncompliant
  // ...
}
{% endhighlight %}


## Solution

### Method #1

{% highlight java %}
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  URL url = new URL(req.getParameter("url"));

  // The safest way is to match the incoming URL against a whitelist
  if (!urlWhiteList.contains(url.toString()))
    throw new IOException();

  // If whitelisting is not possible, at least make sure that things like file:// and http://localhost are blocked
  InetAddress inetAddress = InetAddress.getByName(url.getHost());
  if (!url.getProtocol().startsWith("http") ||
      inetAddress.isAnyLocalAddress() ||
      inetAddress.isLoopbackAddress() ||
      inetAddress.isLinkLocalAddress())
    throw new IOException();

  HttpURLConnection conn = (HttpURLConnection) url.openConnection();
  // ...
}
{% endhighlight %}
