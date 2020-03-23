---
layout: post
title:  "Cleartext Transmission of Sensitive Information Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net transmission cleartext
description: Cleartext Transmission of Sensitive Information Prevention in php, asp.net and java
---
# What is Cleartext Transmission ?

Sensitive data must be protected when it is transmitted through the network. 
As a rule of thumb if data must be protected when it is stored, this data must also be protected during transmission. Some examples for sensitive data are:

- Information used in authentication (e.g. Credentials, PINs, Session identifiers, Tokens, Cookies…)
- Information protected by laws, regulations or specific organizational policy (e.g. Credit Cards, Customers data)

If the application transmits sensitive information via unencrypted channels - e.g. HTTP - it is considered a security risk. Some examples are Basic authentication which sends authentication credentials in plain-text over HTTP, form based authentication credentials sent via HTTP, or plain-text transmission of any other information considered sensitive due to regulations, laws, organizational policy or application business logic.


## Examples for Personal Identifying Information (PII) are:

- Social security numbers
- Bank account numbers
- Passport information
- Healthcare related information
- Medical insurance information
- Student information
- Credit and debit card numbers
- Drivers license and State ID information


# Prevention

## Example #1

For example is authentication forms which transmit user authentication credentials over HTTP. In the example below one can see HTTP being used in the "action" attribute of the form. It is also possible to see this issue by examining the HTTP traffic with an interception proxy.


{% highlight php	 %}
<form action="http://example.com/login">
	<label for="username">User:</label> <input type="text" id="username" name="username" value=""/><br />
	<label for="password">Password:</label> <input type="password" id="password" name="password" value=""/>
	<input type="submit" value="Login"/>
</form>
{% endhighlight %}

## Solution

Use secure channel

Examples of insecure network protocols and their secure alternatives include:

Web Access: HTTPS
File transfer: FTPS, SFTP, SCP, WebDAV over HTTPS
Remote Shell: SSH2 terminal
Remote desktop: radmin, RDP
