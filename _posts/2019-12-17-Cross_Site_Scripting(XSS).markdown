---
layout: post
title:  "Cross Site Scripting(XSS) Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net xss script javascript html
description: Cross Site Scripting(XSS) Prevention in php, asp.net and java
---
# What is Cross Site Scripting(XSS)?

# Reflected

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

Suppose a website has a search function which receives the user-supplied search term in a URL parameter:


https://insecure-website.com/search?term=gift


The application echoes the supplied search term in the response to this URL:


<p>You searched for: gift</p>


Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this:


https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>

This URL results in the following response:

<p>You searched for: <script>/* Bad stuff here... */</script></p>

If another user of the application requests the attacker's URL, then the script supplied by the attacker will execute in the victim user's browser, in the context of their session with the application.


# Stored

Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:


POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net

After this comment has been submitted, any user who visits the blog post will receive the following within the application's response:


<p>This post was extremely helpful.</p>


Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment like this:

<script>/* Bad stuff here... */</script>

Within the attacker's request, this comment would be URL-encoded as:

comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E

Any user who visits the blog post will now receive the following within the application's response:

<p><script>/* Bad stuff here... */</script></p>

The script supplied by the attacker will then execute in the victim user's browser, in the context of their session with the application.


# DOM

DOM-based XSS (also known as DOM XSS) arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data to a potentially dangerous sink within the DOM.


Source: 

A source is a JavaScript property that contains data that an attacker could potentially control. An example of a source is location.search, which reads input from the query string.

A source is a JavaScript property that contains data that an attacker could potentially control. An example of a source is location.search, which reads input from the query string.


Sink: 

A sink is a function or DOM object that allows JavaScript code execution or rendering of HTML. An example of a code execution sink is eval, and an example of an HTML sink is document.body.innerHTML.


A sink is a function or DOM object that allows JavaScript code execution or rendering of HTML. An example of a code execution sink is eval, and an example of an HTML sink is document.body.innerHTML.


Imagine the page http://www.example.com/test.html that contains the below JavaScript code:


<script>
   document.write("<b>Current URL</b> : " + document.baseURI);
</script>

If you send a HTTP request like http://www.example.com/test.html#<script>alert(1)</script>, simple enough your JavaScript code will get executed, because the page is writing whatever you typed in the URL to the page with document.write function. If you look at the source of the page, you won't see <script>alert(1)</script> because it's all happening in the DOM and done by the executed JavaScript code.




After the malicious code is executed by page, you can simply exploit this DOM based cross-site scripting vulnerability to steal the cookies from the user's browser or change the behaviour of the page on the web application as you like.


## Popular Sources

- document.URL
- document.documentURI
- location.href
- location.search
- location.*
- window.name
- document.referrer

## Popular Sinks

- HTML Modification sinks
-- document.write
-- (element).innerHTML

- HTML modification to behaviour change
-- (element).src (in certain elements)

- Execution Related sinks
-- eval
-- setTimout / setInterval
-- execScript

# Prevention

## PHP

### Example #1



{% highlight php %}
<?php
   $name=$_GET['name'];
   print $name;
?>
{% endhighlight %}


## Solution 

### Method #1



{% highlight php %}
<?php
/*
 * XSS filter 
 *
 * This was built from numerous sources
 * (thanks all, sorry I didn't track to credit you)
 * 
 * It was tested against *most* exploits here: http://ha.ckers.org/xss.html
 * WARNING: Some weren't tested!!!
 * Those include the Actionscript and SSI samples, or any newer than Jan 2011
 *
 *
 * TO-DO: compare to SymphonyCMS filter:
 * https://github.com/symphonycms/xssfilter/blob/master/extension.driver.php
 * (Symphony's is probably faster than my hack)
 */

function xss_clean($data)
{
        // Fix &entity\n;
        $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

        // Remove any attribute starting with "on" or xmlns
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

        // Remove javascript: and vbscript: protocols
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do
        {
                // Remove really unwanted tags
                $old_data = $data;
                $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        }
        while ($old_data !== $data);

        // we are done...
        return $data;
}
   $name=xss_clean($_GET['name']);
   print $name;
?>
{% endhighlight %}

## ASP.NET


### Example #1




{% highlight c# %}
/*
* https://gist.github.com/DinisCruz/3fa6893bc85a9fcacdf6
*/
  public static class HtmlControls_ExtensionMethods
    {
        public static string renderControl(this Control control)
        {
            var stringBuilder = new StringBuilder();
            using (var stringWriter = new StringWriter(stringBuilder))
                using (var htmlTextWriter = new HtmlTextWriter(stringWriter))
           
                    control.RenderControl(htmlTextWriter);
            return stringBuilder.str();
        }

    }

    [TestFixture]
    class XSS_Web_Controls
    {        

        [Test]
        public void HtmlTitle()
        {
            var html_Before = "<title>\r\n\t";
            var html_After  = "\r\n</title>";

            Func<string, string> render_Payload = (payload) =>
                {
                    var htmlTitle = new HtmlTitle {Text = payload};
                    return htmlTitle.renderControl();
                };

            Action<string> test_Payload = (payload) =>
                {
                    render_Payload(payload).assert_Is(html_Before + payload + html_After);
                };

            test_Payload("aa '\"> bb <b1> cc ");
            test_Payload("<script>alert(42)</script>");
            test_Payload("aaa</title></head><body><img src=xxx onerror=alert(42) />");            
        }
{% endhighlight %}

## Solution

### Method #1



{% highlight c# %}
 /*
 * https://gist.github.com/DinisCruz/3fa6893bc85a9fcacdf6
 */
   public static class HtmlControls_ExtensionMethods
    {
        public static string render_Control(this Control control)
        {
            var stringBuilder = new StringBuilder();
            using (var stringWriter = new StringWriter(stringBuilder))
                using (var htmlTextWriter = new HtmlTextWriter(stringWriter))
           
                    control.RenderControl(htmlTextWriter);
            return stringBuilder.str();
        }

        public static string set_Text_and_Render_Control<T>(this T control, string text) where T : Control
        {
            control.invoke("set_Text", text);
            return control.render_Control();
        }

        public static T assert_Text_Render<T>(this T control, string html_Before, string html_After, string text) where T : Control
        {
            control.set_Text_and_Render_Control(text).assert_Is(html_Before + text + html_After);
            return control;
        }
    }

    [TestFixture]
    class XSS_Web_Controls
    {
        string payload_1 = "aa '\"> bb <b1> cc ";
        string payload_2 = "<script>alert(42)</script>";
        string payload_3 = "aaa</title></head><body><img src=xxx onerror=alert(42) />";

        [Test]
        public void HtmlTitle()
        {
            var html_Before = "<title>\r\n\t";
            var html_After  = "\r\n</title>";
            

            new HtmlTitle().assert_Text_Render(html_Before, html_After, payload_1)
                           .assert_Text_Render(html_Before, html_After, payload_2)
                           .assert_Text_Render(html_Before, html_After, payload_3);
            
        }

        [Test]
        public void Literal()
        {
            var html_Before = "";
            var html_After  = "";

            new Literal().assert_Text_Render(html_Before, html_After, payload_1)
                         .assert_Text_Render(html_Before, html_After, payload_2)
                         .assert_Text_Render(html_Before, html_After, payload_3);

        }

        [Test]
        public void LinkButton()
        {
            var html_Before = "<a>";
            var html_After  = "</a>";

            new LinkButton().assert_Text_Render(html_Before, html_After, payload_1)
                            .assert_Text_Render(html_Before, html_After, payload_2)
                            .assert_Text_Render(html_Before, html_After, payload_3);
        }
        
    }
{% endhighlight %}


## JAVA

### Example #1



{% highlight java %}
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>XSS Vulnerable</title>
</head>
<body>
	<form action="xss-vuln.jsp" method="post">
		Enter your name: <input type="text" name="name"><input type="submit">
	</form>

<%
 	if(request.getMethod().equalsIgnoreCase("post"))
 	{
 		String name = request.getParameter("name");
 		if(!name.isEmpty())
 		{
			out.println("<br>Hi "+name+". How are you?");
 		}
 	}
%>

</body>
</html>
{% endhighlight %}

## Solution

### Method #1



{% highlight java %}
<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
Patch
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>XSS Patched</title>
</head>
<body>
	<form action="xss-patch.jsp" method="post">
		Enter your name: <input type="text" name="name"><input type="submit">
	</form>

<%
 	if(request.getMethod().equalsIgnoreCase("post"))
 	{
 		String name = StringEscapeUtils.escapeHtml(request.getParameter("name"));
 		if(!name.isEmpty())
 		{
			out.println("<br>Hi "+name+". How are you?");
 		}
 	}
%>
</body>
</html>
{% endhighlight %}
