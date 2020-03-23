---
layout: post
title:  "File Inclusion Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net request inclusion include lfi rfi 
description: File Inclusion Prevention in php, asp.net and java
---
# What is File Inclusion ?

File inclusions are part of every advanced server side scripting language on the web. They are needed to keep web applications' code tidy and maintainable. They also allow web applications to read files from the file system, provide download functionality, parse configuration files and do other similar tasks. Though if not implemented properly, attackers can exploit them and craft a LFI attack which may lead to information disclosure, cross-site-Scripting (XSS) and remote code execution (RFI) vulnerabilities.

To keep a website's code readable and modular the code is usually split into multiple files and directories, ideally separated into logical pieces. To tell the interpreter where those files are you have to specify a correct file path and pass it to a function. This function will open the file and include it inside the document. This way the parser sees it as valid code and interprets it accordingly.


### Usage Example


You create several different modules for one page and to include them you use the GET parameter with the filename of the respective function, such as:


{% highlight php	 %}
https://example.com/?module=contact.php
{% endhighlight %}

The Risks of Introducing a Local File Inclusion Vulnerability


If the developer fails to implement sufficient filtering an attacker could exploit the local file inclusion vulnerability by replacing contact.php with the path of a sensitive file such as the passwd file, where passwords are stored on a Unix system, allowing the attacker to see its content:

{% highlight php	 %}
https://example.com/?module=/etc/passwd
{% endhighlight %}

In such a scenario the malicious hacker could also inject code from somewhere else on the web server and let the parser interpret it as instructions to exploit the LFI vulnerability. A good way to do that is a picture upload functionality with an image containing malicious code in its source, such as:

{% highlight php	 %}
https://example.com/?module=uploads/avatar102.gif
{% endhighlight %}


# Prevention
 
- Save the file paths in a database and assign an ID to each of them. BY doing so users can only see the ID and are not able to view or change the path.
- Use a whitelist of files and ignore every other filename and path.
- Instead of including files on the web server, store their content in databases where possible.
- Instruct the server to automatically send download headers and not execute files in a specific directory such as /download/. That way you can point the user directly to the file on the server without having to write additional code for the download. An example link could look like https://example.com/downloads/brochure2.pdf



## PHP

### Example #1


{% highlight php %}
<?php
$filename = $_GET["filename"];
include $filename . ".php";
?>
{% endhighlight %}

## Solution

### Method #1

{% highlight php %}
$allowedPages = array('go.php', 'stop.php', 'file.php');
  $filename = $_GET['page'];

  if(in_array($filename, $allowedPages) && file_exists($filename)){
    include ($filename);
  }else{
    //output error
  }
{% endhighlight %}

## ASP.NET


### Example #1

{% highlight c# %}
http://abcd.com/<vuln.page>?<vuln query string>

Consider the below code:

public partial class Downloads_Download : System.Web.UI.Page
{
  string sBasePath="";
  protected void Page_Load(object sender, EventArgs e)
  {

    try
    {
      string filename = Request.QueryString["fname"];
      string sBasePath = System.Web.HttpContext.Current.Request.ServerVariables["APPL_PHYSICAL_PATH"];
      if (sBasePath.EndsWith("\\"))
        sBasePath = sBasePath.Substring(0, sBasePath.Length - 1);
      sBasePath = sBasePath + "\\" + ConfigurationManager.AppSettings["FilesPath"] + "\\" + filename; 
      Response.AddHeader("content-disposition", String.Format("attachment;filename={0}", filename));
      Response.WriteFile(sBasePath);
    }
    catch (Exception ex)
    {
Response.Redirect("~/Error.aspx?message=" + ex.Message.ToString() + " path=" + sBasePath);
    }
  }
}
{% endhighlight %}

## Solutions

### Method #1

{% highlight c# %}
protected void Page_Load(object sender, EventArgs e)
  {
    //string file = Server.MapPath(HttpUtility.UrlEncode(functions.RF("file")));
    string file = Server.MapPath(functions.RQ("file"));
    if (File.Exists(file))
    {
      Regex reg = new Regex(@"\.(\w+)$");
      string ext = reg.Match(file).Groups[1].Value;
      switch (ext)
      {
        case "xls":
          Response.ContentType = "application/vnd.ms-excel";
          break;
        case "xlsx":
          Response.ContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
          break;
        case "ppt":
          Response.ContentType = "application/vnd.ms-powerpoint";
          break;
        case "pptx":
          Response.ContentType = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
          break;
        default:
      Response.ContentType = " application/pdf ";
          break;
      }
      byte[] buffer = File.ReadAllBytes(file);
      Response.OutputStream.Write(buffer, 0, buffer.Length);
      Response.AddHeader("Content-Disposition", "attachment;filename=" + Path.GetFileName(file));
    }
    else
    {      
      Response.Write("This file Extension is not allowed");
    }
  }
{% endhighlight %}

## JAVA

### Example #1


{% highlight java %}
<%@ page pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<c:set var="language" value="${not empty param.language ? param.language : not empty language ? language : pageContext.request.locale}" scope="session" />
<fmt:setLocale value="${language}" />
<fmt:setBundle basename="messages" />
<!DOCTYPE html>
<html>
<head>
<title><fmt:message key="title.design.test.page" /></title>
<link rel="icon" type="image/vnd.microsoft.icon" href="${pageContext.request.contextPath}/images/favicon.ico">
<c:catch var="ex">
    <c:if test="${param.template != null && !fn:contains(param.template,'../') && !fn:startsWith(param.template,'/')}">
        <c:import url="<%=request.getParameter(\"template\")%>" />
    </c:if>
</c:catch>
</head>
<body style="margin-left: 20px; margin-right: 20px;">
    <table style="width: 100%;">
        <tr>
            <td>
                <h2>
                    <span class="glyphicon glyphicon-globe"></span>&nbsp;
                    <fmt:message key="title.design.test.page" />
                </h2>
            </td>
            <td align="right"><a href="${pageContext.request.contextPath}/"><fmt:message key="label.go.to.main" /></a></td>
        </tr>
    </table>
    <hr style="margin-top: 0" />
    <header>
        <table style="width: 720px;">
            <tr>
                <td><img src="${pageContext.request.contextPath}/images/easybuggy.png"></td>
                <td><fmt:message key="description.design.page" /></td>
            </tr>
        </table>
    </header>
    <hr style="margin-top: 10px" />
    <p>
        <fmt:message key="description.design.test" />
    </p>
    <ul>
        <li><p>
                <a href="includable.jsp"><fmt:message key="style.name.nonstyle" /></a>:
                <fmt:message key="style.description.nonstyle" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_bootstrap.html"><fmt:message key="style.name.bootstrap" /></a>:
                <fmt:message key="style.description.bootstrap" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_google_mdl.html"><fmt:message key="style.name.google.mdl" /></a>:
                <fmt:message key="style.description.google.mdl" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_materialize.html"><fmt:message key="style.name.materialize" /></a>:
                <fmt:message key="style.description.materialize" />
            </p></li>
    </ul>
    <br>
    <div class="alert alert-info" role="alert">
        <span class="glyphicon glyphicon-info-sign"></span>&nbsp;
        <fmt:message key="msg.note.dangerous.file.inclusion" />
    </div>
    <hr>
    <footer>
        <img src="/images/easybuggyL.png">Copyright &copy; 2017 T246 OSS Lab, all rights reserved.
    </footer>
</body>
</html>

{% endhighlight %}


## Solution

### Method #1

{% highlight java %}
<%@ page pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%
    // host will typically equal: uk.domain.com or fr.domain.com
    String host = request.getServerName();
    // cc is attempting to become the country code for the domain
    String cc = host.substring(0, host.indexOf("."));
%>
<c:set var="language" value="${not empty param.language ? param.language : not empty language ? language : pageContext.request.locale}" scope="session" />
<fmt:setLocale value="${language}" />
<fmt:setBundle basename="messages" />
<!DOCTYPE html>
<html>
<head>
<title><fmt:message key="title.design.test.page" /></title>
<link rel="icon" type="image/vnd.microsoft.icon" href="${pageContext.request.contextPath}/images/favicon.ico">
<c:catch var="ex">
    <c:if test="${param.template != null && !fn:contains(param.template,'../') && !fn:startsWith(param.template,'/')}">
        
        <c:import url="http://assets.domain.com/${cc}/includes/<%=request.getParameter(\"template\")%>.jsp" />
    </c:if>
</c:catch>
</head>
<body style="margin-left: 20px; margin-right: 20px;">
    <table style="width: 100%;">
        <tr>
            <td>
                <h2>
                    <span class="glyphicon glyphicon-globe"></span>&nbsp;
                    <fmt:message key="title.design.test.page" />
                </h2>
            </td>
            <td align="right"><a href="${pageContext.request.contextPath}/"><fmt:message key="label.go.to.main" /></a></td>
        </tr>
    </table>
    <hr style="margin-top: 0" />
    <header>
        <table style="width: 720px;">
            <tr>
                <td><img src="${pageContext.request.contextPath}/images/easybuggy.png"></td>
                <td><fmt:message key="description.design.page" /></td>
            </tr>
        </table>
    </header>
    <hr style="margin-top: 10px" />
    <p>
        <fmt:message key="description.design.test" />
    </p>
    <ul>
        <li><p>
                <a href="includable.jsp"><fmt:message key="style.name.nonstyle" /></a>:
                <fmt:message key="style.description.nonstyle" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_bootstrap.html"><fmt:message key="style.name.bootstrap" /></a>:
                <fmt:message key="style.description.bootstrap" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_google_mdl.html"><fmt:message key="style.name.google.mdl" /></a>:
                <fmt:message key="style.description.google.mdl" />
            </p></li>
        <li><p>
                <a href="includable.jsp?template=style_materialize.html"><fmt:message key="style.name.materialize" /></a>:
                <fmt:message key="style.description.materialize" />
            </p></li>
    </ul>
    <br>
    <div class="alert alert-info" role="alert">
        <span class="glyphicon glyphicon-info-sign"></span>&nbsp;
        <fmt:message key="msg.note.dangerous.file.inclusion" />
    </div>
    <hr>
    <footer>
        <img src="/images/easybuggyL.png">Copyright &copy; 2017 T246 OSS Lab, all rights reserved.
    </footer>
</body>
</html>
{% endhighlight %}
