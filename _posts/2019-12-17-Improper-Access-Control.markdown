---
layout: post
title:  "Improper Access Control Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net access authentication broken
description: Improper Access Control Prevention in php, asp.net and java
---
# What is Improper Access Control ?

Your web application is vulnerable to such a flaw if users can access data that should not be accessible to them. In order to determine if your web application is vulnerable, you could simply log in to your web application, visit pages that require authentication in order to be accessed, log out, and pay a visit to those pages once again. If you can access those pages when logged out, you have got a problem – your website is vulnerable to broken access control.


Access control involves the use of several protection mechanisms such as:


- Authentication (proving the identity of an actor)
- Authorization (ensuring that a given actor can access a resource), and
- Accountability (tracking of activities that were performed)


When any mechanism is not applied or otherwise fails, attackers can compromise the security of the software by gaining privileges, reading sensitive information, executing commands, evading detection, etc.


There are two distinct behaviors that can introduce access control weaknesses:


- Specification: incorrect privileges, permissions, ownership, etc. are explicitly specified for either the user or the resource (for example, setting a password file to be world-writable, or giving administrator capabilities to a guest user). This action could be performed by the program or the administrator.


- Enforcement: the mechanism contains errors that prevent it from properly enforcing the specified access control requirements (e.g., allowing the user to specify their own privileges, or allowing a syntactically-incorrect ACL to produce insecure settings). This problem occurs within the program itself, in that it does not actually enforce the intended security policy that the administrator specifies.


# Prevention

- With the exception of public resources, deny by default.
- Model access controls should enforce record ownership, rather than accepting that the user can create, read, update, or delete any record.

## PHP

### Example #1



{% highlight php %}
<?php 
include("inc/css.php"); 
session_start();
?>
<html>
<head>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.php">Log Out</a></li>
</div>

</div>

<?php include("inc/js.php"); ?>
</body>
</html>
{% endhighlight %}

## Solution

### Method #1



{% highlight php %}
<?php 
include("inc/css.php"); 
session_start();
if(!isset($_SESSION['user'])){
   header("Location:login.php");
   exit;
}
?>
<html>
<head>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.php">Log Out</a></li>
</div>

</div>

<?php include("inc/js.php"); ?>
</body>
</html>
{% endhighlight %}

## ASP.NET


### Example #1



{% highlight c# %}
<%@ Page Language="C#" AutoEventWireup="true"  %>
<%@ Register Namespace="Active.Web.UI.Controls" Assembly="Active.Web.UI.Controls" TagPrefix="active" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Dashboard Page</title>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.jsp">Log Out</a></li>
</div>

</div>
</body>
</html>
{% endhighlight %}


## Solution

### Method #1



{% highlight c# %}

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Dashboard Page</title>
    <script runat="server">
        protected override void OnLoad(object sender, EventArgs e)
        {
            if (Session["User_ID"])==null)
             {
                Response.Redirect("login.aspx");
             } 
        }
    </script>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.jsp">Log Out</a></li>
</div>

</div>
</body>
</html>
{% endhighlight %}

## JAVA

### Example #1



{% highlight java %}
<html>
<head>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.jsp">Log Out</a></li>
</div>

</div>

</body>
</html>
{% endhighlight %}

## Solution

### Method #1



{% highlight java %}

    session=request.getSession(false);
    if(session.getAttribute("User_ID")==null)
    {
        response.sendRedirect("login.jsp");
    }



<html>
<head>
</head>
<body>
<form action="" method="post">

<div class="member-page">

<div class="form-group">
<h4>Member's Area</h4>
</div>

<div class="dashboard">
<h6>

<div class="form-group">
<li><a href="?action=account">My Account</a></li>
</div>

<div class="form-group">
<li><a href="?action=download">Download Software</a></li>
</div>

<div class="form-group">
<li><a href="?action=tickets">Create a Support Ticket</a></li>
</div>

<div class="form-group">
<li><a href="?action=resources">Member Resources</a></li>
</div>

<div class="form-group">
<li><a href="?action=logout.jsp">Log Out</a></li>
</div>

</div>

</body>
</html>
{% endhighlight %}
