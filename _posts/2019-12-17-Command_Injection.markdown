---
layout: post
title:  "Command Injection Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net command injection
description: Command Injection Prevention in php, asp.net and java
---
# What is Command injection ?

Command injection is basically injection of operating system commands to be executed through a web-app. The purpose of the command injection attack is to inject and execute commands specified by the attacker in the vulnerable application. 

In situation like this, the application, which executes unwanted system commands, is like a pseudo system shell, and the attacker may use it as any authorized system user. However, commands are executed with the same privileges and environment as the web application has. 

Command injection attacks are possible due to lack of correct input data validation, which can be manipulated by the attacker (forms, cookies, HTTP headers etc.).

Typically, Code Injection occurs when an application evaluates code without validating it first. The following is a source code of an example PHP application with a Code Injection bug.

{% highlight php %}
/**
* Get the code from a GET input
* Example - http://example.com/?code=phpinfo();
*/
$code = $_GET['code'];

/**
* Unsafely evaluate the code
* Example - phpinfo();
*/
eval("\$code;");
{% endhighlight %}


Base on the above example, an attacker could use the following construct to execute arbitrary PHP code. As a result, the PHP info page would be displayed.

{% highlight php %}
http://example.com/?code=phpinfo();
{% endhighlight %}



## OS Command Execution


An attacker may be able to escalate a Code Injection vulnerability even further by executing arbitrary operating system commands on the server. Based on the example above, the attacker can execute the whoami shell command using the system() function in PHP.

{% highlight php %}
http://example.com/?code=system('whoami');
{% endhighlight %}



Once an attacker is able to execute OS commands, they could attempt to use a web shell or install other malware. From there, an attacker may even attempt to compromise other internal systems.


# Prevention

By far the most effective way to prevent OS command injection vulnerabilities is to never call out to OS commands from application-layer code. In virtually every case, there are alternate ways of implementing the required functionality using safer platform APIs.

If it is considered unavoidable to call out to OS commands with user-supplied input, then strong input validation must be performed. Some examples of effective validation include:


- Validating against a whitelist of permitted values.
- Validating that the input is a number.
- Validating that the input contains only alphanumeric characters, no other syntax or whitespace.

Never attempt to sanitize input by escaping shell metacharacters. In practice, this is just too error-prone and vulnerable to being bypassed by a skilled attacker.


## PHP

### Example #1



{% highlight php %}
<html>
<head>
    <title>Command Injection</title>
</head>
<body>
<form action="" method="get">
    Ping address: <input type="text" name="addr">
    <input type="submit">
</form>
</body>
</html>
<?php
#Excute Command
echo shell_exec("ping ".$_GET['addr']);
?>
{% endhighlight %}

this code vulnerable because if send 127.0.0.1;ls or 127.0.0.1%26%26dir run two commands with shell_exec


### Example #2



{% highlight php %}
<html>
<head>
    <title>Command Injection</title>
</head>
<body>
<form action="" method="get">
    Ping address: <input type="text" name="addr">
    <input type="submit">
</form>
</body>
</html>
<?php
#Excute Command
shell_exec("ping ".$_GET['addr']);
?>
{% endhighlight %}

this code vulnerable because if send 127.0.0.1;sleep 5 or 127.0.0.1%26%26timeout 5 run two commands with shell_exec


## Solutions

### Method #1



{% highlight php %}
<html>
<head>
    <title>Command Injection</title>
</head>
<body>
<form action="" method="get">
    Ping address: <input type="text" name="addr">
    <input type="submit">
</form>
</body>
</html>
<?php
#Excute Command
echo shell_exec(escapeshellcmd("ping ".$_GET['addr']));
?>
{% endhighlight %}


### Method #2



{% highlight php %}
<?php
function isAllowed($cmd){
    // If the ip is matched, return true
    if(filter_var($cmd, FILTER_VALIDATE_IP)) {
        return true;
    }

    return false;
}
#Excute Command
if (isAllowed($_GET['addr'])) {
    echo shell_exec("ping ".$_GET['addr']);
}
?>
{% endhighlight %}


## ASP.NET


### Example #1



{% highlight c# %}
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e){
}
string ExcuteCmd(string arg){
	ProcessStartInfo psi = new ProcessStartInfo();
	psi.FileName = "cmd.exe";
	psi.Arguments = "/c ping -n 2 " + arg;
	psi.RedirectStandardOutput = true;
	psi.UseShellExecute = false;
	Process p = Process.Start(psi);
	StreamReader stmrdr = p.StandardOutput;
	string s = stmrdr.ReadToEnd();
	stmrdr.Close();
	return s;
}
void cmdExe_Click(object sender, System.EventArgs e){
	Response.Write(Server.HtmlEncode(ExcuteCmd(addr.Text)));
}
</script>

<HTML>
<HEAD>
<title>ASP.NET Ping Application</title>
</HEAD>
<body>
<form id="cmd" method="post" runat="server">
<asp:Label id="lblText" runat="server">Command:</asp:Label>
<asp:TextBox id="addr" runat="server" Width="250px">
</asp:TextBox>
<asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click">
</asp:Button>
</form>
</body>
</HTML>
{% endhighlight %}


### Example #2



{% highlight c# %}
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="C#" runat="server">
string ExcuteCmd(string arg){
  ProcessStartInfo psi = new ProcessStartInfo();
  psi.FileName = "cmd.exe";
  psi.Arguments = "/c ping -n 2 " + arg;
  psi.RedirectStandardOutput = true;
  psi.UseShellExecute = false;
  Process p = Process.Start(psi);
  StreamReader stmrdr = p.StandardOutput;
  string s = stmrdr.ReadToEnd();
  stmrdr.Close();
  return s;
}
void Page_Load(object sender, System.EventArgs e){
  string addr = Request.QueryString["addr"];
  Server.HtmlEncode(ExcuteCmd(addr));
}
</script>

<HTML>
<HEAD>
<title>ASP.NET Ping Application</title>
</HEAD>
<body>
<form id="cmd" method="GET" runat="server">
</form>
</body>
</HTML>
{% endhighlight %}


## Solutions

### Method #1



{% highlight c# %}
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
    void Page_Load(object sender, EventArgs e){
    }
    Boolean Blacklist(string address)
    {
        string[] black_array = { "192.168.1.1", "127.0.0.1" };
        Match match = Regex.Match(address, @"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$");
        if (match.Success)
        {
            if (black_array.Contains(address))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        return false;

    }
    string ExcuteCmd(string arg){
        if (Blacklist(arg)) {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c ping -n 2 " + arg;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            StreamReader stmrdr = p.StandardOutput;
            string s = stmrdr.ReadToEnd();
            stmrdr.Close();
            return s;
        }
        else
        {
            return "Access Denied";
        }

    }
    void cmdExe_Click(object sender, System.EventArgs e){
        Response.Write(Server.HtmlEncode(ExcuteCmd(addr.Text)));
    }
</script>

<HTML>
<HEAD>
<title>ASP.NET Ping Application</title>
</HEAD>
<body>
<form id="cmd" method="post" runat="server">
<asp:Label id="lblText" runat="server">Command:</asp:Label>
<asp:TextBox id="addr" runat="server" Width="250px">
</asp:TextBox>
<asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click">
</asp:Button>
</form>
</body>
</HTML>
{% endhighlight %}

### Method #2



{% highlight c# %}
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
    void Page_Load(object sender, EventArgs e){
    }
    String SafeString(string address)
    {
        char[] separators = new char[]{' ',';',',','\r','\t','\n','&'};

        string[] temp = address.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        address = String.Join("\n", temp);
        return address;
    }
    Boolean Blacklist(string address)
    {
        address = SafeString(address); 
        string[] black_array = { "192.168.1.1", "127.0.0.1" };
        if (black_array.Contains(address))
        {
            return false;
        }
        else
        {

            return true;
        }
    }
    string ExcuteCmd(string arg){
        if (Blacklist(arg)) {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c ping -n 2 " + arg;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            StreamReader stmrdr = p.StandardOutput;
            string s = stmrdr.ReadToEnd();
            stmrdr.Close();
            return s;
        }
        else
        {
            return "Access Denied";
        }

    }
    void cmdExe_Click(object sender, System.EventArgs e){
        Response.Write(Server.HtmlEncode(ExcuteCmd(SafeString(addr.Text))));
    }
</script>

<HTML>
<HEAD>
<title>ASP.NET Ping Application</title>
</HEAD>
<body>
<form id="cmd" method="post" runat="server">
<asp:Label id="lblText" runat="server">Command:</asp:Label>
<asp:TextBox id="addr" runat="server" Width="250px">
</asp:TextBox>
<asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click">
</asp:Button>
</form>
</body>
</HTML>
{% endhighlight %}


## Java

### Example #1



{% highlight  java %}
package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/ognleijc" })
public class OGNLExpressionInjectionServlet extends AbstractServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        Locale locale = req.getLocale();
        StringBuilder bodyHtml = new StringBuilder();
        Object value = null;
        String errMessage = "";
        OgnlContext ctx = new OgnlContext();
        String expression = req.getParameter("expression");
        if (!StringUtils.isBlank(expression)) {
            try {
                Object expr = Ognl.parseExpression(expression.replaceAll("Math\\.", "@Math@"));
                value = Ognl.getValue(expr, ctx);
            } catch (OgnlException e) {
                if (e.getReason() != null) {
                    errMessage = e.getReason().getMessage();
                }
                log.debug("OgnlException occurs: ", e);
            } catch (Exception e) {
                log.debug("Exception occurs: ", e);
            } catch (Error e) {
                log.debug("Error occurs: ", e);
            }
        }

        bodyHtml.append("<form action=\"ognleijc\" method=\"post\">");
        bodyHtml.append(getMsg("msg.enter.math.expression", locale));
        bodyHtml.append("<br><br>");
        if (expression == null) {
            bodyHtml.append("<input type=\"text\" name=\"expression\" size=\"80\" maxlength=\"300\">");
        } else {
            bodyHtml.append("<input type=\"text\" name=\"expression\" size=\"80\" maxlength=\"300\" value=\""
                    + encodeForHTML(expression) + "\">");
        }
        bodyHtml.append(" = ");
        if (value != null && NumberUtils.isNumber(value.toString())) {
            bodyHtml.append(value);
        }
        bodyHtml.append("<br><br>");
        bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.calculate", locale) + "\">");
        bodyHtml.append("<br><br>");
        if (value == null && expression != null) {
            bodyHtml.append(getErrMsg("msg.invalid.expression", new String[] { errMessage }, locale));
        }
        bodyHtml.append(getInfoMsg("msg.note.commandinjection", locale));
        bodyHtml.append("</form>");

        responseToClient(req, res, getMsg("title.commandinjection.page", locale), bodyHtml.toString());
    }
}
{% endhighlight %}


### Example #2



{% highlight  java %}
package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * @author  JoyChou (joychou@joychou.org)
 * @date    2018.05.24
 * @desc    Java code execute
 * @fix     过滤造成命令执行的参数
 */

@Controller
@RequestMapping("/rce")
public class Rce {

    @RequestMapping("/exec")
    @ResponseBody
    public String CommandExec(HttpServletRequest request) {
        String cmd = request.getParameter("cmd").toString();
        Runtime run = Runtime.getRuntime();
        String lineStr = "";

        try {
            Process p = run.exec(cmd);
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                lineStr += tmpStr + "\n";
                System.out.println(tmpStr);
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "command exec failed";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
            return "Except";
        }
        return lineStr;
    }
}
{% endhighlight %}


## Solutions


### Method #1



{% highlight  java %}
package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

/**
 * @author  JoyChou (joychou@joychou.org)
 * @fix     RezaDuty 
 */

@Controller
@RequestMapping("/rce")
public class Rce {

    @RequestMapping("/exec")
    @ResponseBody
    public String CommandExec(HttpServletRequest request) {
    	
    	
    	String lineStr = "";
        String cmd = request.getParameter("cmd").toString();
        if(WhiteCommand(cmd)) {
	        Runtime run = Runtime.getRuntime();
	        
	
	        try {
	            Process p = run.exec(cmd);
	            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
	            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
	            String tmpStr;
	
	            while ((tmpStr = inBr.readLine()) != null) {
	                lineStr += tmpStr + "\n";
	                System.out.println(tmpStr);
	            }
	
	            if (p.waitFor() != 0) {
	                if (p.exitValue() == 1)
	                    return "command exec failed";
	            }
	
	            inBr.close();
	            in.close();
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Except";
	        }
	       
        }
        return lineStr;
    }
    public Boolean WhiteCommand(String cmd) {
    	String[] splited = cmd.split("\\s+");
    	String [] whitelist = {"echo","whoami" };
    	if(Arrays.asList(whitelist).contains(splited[0])){
    	    return true;
    	}else {
    		return false;
    	}
    }
}
{% endhighlight %}

### Method #2



{% highlight  java %}
package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

/**
 * @author  JoyChou (joychou@joychou.org)
 * @fix     RezaDuty 
 */

@Controller
@RequestMapping("/rce")
public class Rce {

    @RequestMapping("/exec")
    @ResponseBody
    public String CommandExec(HttpServletRequest request) {
    	
    	
    	String lineStr = "";
        String ip = request.getParameter("address").toString();
        
	        Runtime run = Runtime.getRuntime();
	        
	    	if(validate(ip) && WhiteAddress(ip)) {
		        try {
		            Process p = run.exec("ping -n 1 "+ip);
		            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
		            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
		            String tmpStr;
		
		            while ((tmpStr = inBr.readLine()) != null) {
		                lineStr += tmpStr + "\n";
		                System.out.println(tmpStr);
		            }
		
		            if (p.waitFor() != 0) {
		                if (p.exitValue() == 1)
		                    return "command exec failed";
		            }
		
		            inBr.close();
		            in.close();
		        } catch (Exception e) {
		            e.printStackTrace();
		            return "Except";
		        }
		} 
	        return lineStr;
		
	    }
	    public static boolean validate(final String ip) {
	        String PATTERN = "^((0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)\\.){3}(0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)$";

	        return ip.matches(PATTERN);
	    }
    public Boolean WhiteAddress(String ip) {
    	String [] whitelist = {"127.0.0.1","192.168.1.1" };
    	if(!Arrays.asList(whitelist).contains(ip)){
    	    return true;
    	}else {
    		return false;
    	}
    }
}
{% endhighlight %}
