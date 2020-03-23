---
layout: post
title:  "Session Fixation Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net session access authentication
description: Session Fixation Prevention in php, asp.net and java
---
# What is Session Fixation ?

![sql injection](/images/session_fixation.jpg)

Session Fixation is an attack that permits an attacker to hijack a valid user session. The attack explores a limitation in the way the web application manages the session ID, more specifically the vulnerable web application. When authenticating a user, it doesn’t assign a new session ID, making it possible to use an existent session ID. The attack consists of obtaining a valid session ID (e.g. by connecting to the application), inducing a user to authenticate himself with that session ID, and then hijacking the user-validated session by the knowledge of the used session ID. The attacker has to provide a legitimate Web application session ID and try to make the victim's browser use it.


The session fixation attack is a class of Session Hijacking, which steals the established session between the client and the Web Server after the user logs in. Instead, the Session Fixation attack fixes an established session on the victim's browser, so the attack starts before the user logs in.


There are several techniques to execute the attack; it depends on how the Web application deals with session tokens. Below are some of the most common techniques:


- Session token in the URL argument: The Session ID is sent to the victim in a hyperlink and the victim accesses the site through the malicious URL.
- Session token in a hidden form field: In this method, the victim must be tricked to authenticate in the target Web Server, using a login form developed for the attacker. The form could be hosted in the evil web server or directly in html formatted e-mail.
- Session ID in a cookie
-Client-side script
-meta tag
-HTTP header response

# Prevention

Web applications must ignore any session ID provided by the user's browser at login and must always generate a new session to which the user will log in if successfully authenticated.


## PHP

### Example #1


{% highlight php %}
<?php
// https://gist.github.com/markjames/516977
// Demo for session fixation
// 
// Attacker creates a session by visiting the page: http://famfamfam.com/sessionfixation.php
// Attacker gets their session ID out of the cookie (or in this case from the page)
// Attacker creates a URL such as http://famfamfam.com/sessionfixation.php?PHPSESSID=attackerssessionid and sends it to victim
// Victim clicks the URL (now both the attacker and victim are using the same session)
// Victim logs in
// Now the attacker is logged in to the victim's account too (same session!)

session_start();

if( isset($_GET['password']) && $_GET['password'] == 'blissfulignorance' ) {
	$_SESSION['logged_in'] = true;
	$_SESSION['logged_in_as'] = 'Mark J.';
	
}

if( isset($_SESSION['logged_in']) && $_SESSION['logged_in'] ) {

	echo "You are logged in as ", htmlentities($_SESSION['logged_in_as'],ENT_QUOTES,'UTF-8');

} else {

	echo "You are not logged in";

}

echo "<br>", "Your session ID is " . session_id(); 

?>
{% endhighlight %}

## Solution

### Method #1



{% highlight php %}
<?php
//https://gist.github.com/markjames/516977
// Demo for session fixation
// 
// Attacker creates a session by visiting the page: http://famfamfam.com/sessionfixation.php
// Attacker gets their session ID out of the cookie (or in this case from the page)
// Attacker creates a URL such as http://famfamfam.com/sessionfixation.php?PHPSESSID=attackerssessionid and sends it to victim
// Victim clicks the URL (now both the attacker and victim are using the same session)
// Victim logs in
// Now the attacker is logged in to the victim's account too (same session!)

session_start();

if( isset($_GET['password']) && $_GET['password'] == 'blissfulignorance' ) {
	$_SESSION['logged_in'] = true;
	$_SESSION['logged_in_as'] = 'Mark J.';
	
	session_regenerate_id()
}

if( isset($_SESSION['logged_in']) && $_SESSION['logged_in'] ) {

	echo "You are logged in as ", htmlentities($_SESSION['logged_in_as'],ENT_QUOTES,'UTF-8');

} else {

	echo "You are not logged in";

}

echo "<br>", "Your session ID is " . session_id(); 

?>
{% endhighlight %}

## ASP.NET


### Example #1



{% highlight c# %}
/*
* https://www.codeproject.com/Articles/210993/Session-Fixation-vulnerability-in-ASP-NET
*/
protected void Page_Load(object sender, EventArgs e)
{
    if (Session["LoggedIn"] != null)
    {
        lblMessage.Text = "Congratulations !, you are logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Green;
        btnLogout.Visible = true;
    }
    else
    {
        lblMessage.Text = "You are not logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Red;
    }
}

protected void LoginMe(object sender, EventArgs e)
{
    // Check for Username and password (hard coded for this demo)
    if (txtU.Text.Trim().Equals("u") && txtP.Text.Trim().Equals("p"))
    {
        Session["LoggedIn"] = txtU.Text.Trim();
    }
    else
    {
        lblMessage.Text = "Wrong username or password";
    }
}

protected void LogoutMe(object sender, EventArgs e)
{
    Session.Clear();
    Session.Abandon();
    Session.RemoveAll();
}
{% endhighlight %}

## Solution

### Method #1



{% highlight c# %}
/*
* https://www.codeproject.com/Articles/210993/Session-Fixation-vulnerability-in-ASP-NET
*/
protected void Page_Load(object sender, EventArgs e)
{
    //NOTE: Keep this Session and Auth Cookie check
    //condition in your Master Page Page_Load event
    if (Session["LoggedIn"] != null && Session["AuthToken"] != null 
           && Request.Cookies["AuthToken"] != null)
    {
        if (!Session["AuthToken"].ToString().Equals(
                   Request.Cookies["AuthToken"].Value))
        {
            // redirect to the login page in real application
            lblMessage.Text = "You are not logged in.";
        }
        else
        {
            lblMessage.Text = "Congratulations !, you are logged in.";
            lblMessage.ForeColor = System.Drawing.Color.Green;
            btnLogout.Visible = true;
        }
    }
    else
    {
        lblMessage.Text = "You are not logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Red;
    }
}

protected void LoginMe(object sender, EventArgs e)
{
    // Check for Username and password (hard coded for this demo)
    if (txtU.Text.Trim().Equals("u") && 
                  txtP.Text.Trim().Equals("p"))
    {
        Session["LoggedIn"] = txtU.Text.Trim();
        // createa a new GUID and save into the session
        string guid = Guid.NewGuid().ToString();
        Session["AuthToken"] = guid;
        // now create a new cookie with this guid value
        Response.Cookies.Add(new HttpCookie("AuthToken", guid));

    }
    else
    {
        lblMessage.Text = "Wrong username or password";
    }
}

protected void LogoutMe(object sender, EventArgs e)
{
    Session.Clear();
    Session.Abandon();
    Session.RemoveAll();

    if (Request.Cookies["ASP.NET_SessionId"] != null)
    {
        Response.Cookies["ASP.NET_SessionId"].Value = string.Empty;
        Response.Cookies["ASP.NET_SessionId"].Expires = DateTime.Now.AddMonths(-20);
    }

    if (Request.Cookies["AuthToken"] != null)
    {
        Response.Cookies["AuthToken"].Value = string.Empty;
        Response.Cookies["AuthToken"].Expires = DateTime.Now.AddMonths(-20);
    }
}
{% endhighlight %}

## JAVA

### Example #1



{% highlight java %}
<%@page import="java.sql.*"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title> </title>
</head>
<body>
<%
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	Class.forName("com.mysql.jdbc.Driver");
	Connection con = (Connection) DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "root" , "");
	PreparedStatement ps=(PreparedStatement) con.prepareStatement("select * from users where username=? and password=? limit 0,1");
	ps.setString(1,user);
	ps.setString(2,pass);
	ResultSet rs=ps.executeQuery();
	if(rs.next())
	{
		session.setAttribute("useracc", rs.getString("user"));
		out.println("Login success");
	}
	else
	{
		out.println("Login failed");
	}
%>
</body>
</html>
{% endhighlight %}

## Solution

### Method #1



{% highlight java %}
<%@page import="java.sql.*"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title> </title>
</head>
<body>
<%
	String user = request.getParameter("user");
	String pass = request.getParameter("pass");
	Class.forName("com.mysql.jdbc.Driver");
	Connection con = (Connection) DriverManager.getConnection("jdbc:mysql://localhost:3306/userdb", "root" , "");
	PreparedStatement ps=(PreparedStatement) con.prepareStatement("select * from users where username=? and password=? limit 0,1");
	ps.setString(1,user);
	ps.setString(2,pass);
	ResultSet rs=ps.executeQuery();
	if(rs.next())
	{
		session.invalidate();
		request.getSession(true);
		session.setAttribute("useracc", rs.getString("user"));
		out.println("Login success");
	}
	else
	{
		out.println("Login failed");
	}
%>
</body>
</html>
{% endhighlight %}
