---
layout: post
title:  "NoSQL Injection Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net nosql injection
description: NoSQL Injection Prevention in php, asp.net and java
---
# What is NoSQL injection ?

NoSQL (not only SQL) is a trending term in modern data stores; it refers to nonrelational databases that rely on different storage mechanisms such as document store, key-value store, and graph. 

The wide adoption of these databases has been facilitated by the new requirements of modern large-scale applications, such as Facebook, Amazon, and Twitter,which need to distribute data across a huge number of servers. 

Traditional relational databases don't meet these scalability requirements; they require a single database node to execute all operations of the same transaction.

Web applications and services commonly use NoSQL databases to store customer data. Figure 2 illustrates a typical architecture in which a NoSQL database is used to store the data accessed via a Web application. 

Access to the database is performed via a driver—an access protocol wrapper that provides libraries for database clients in multiple programming languages. Although the drivers themselves might not be vulnerable, sometimes they present unsafe APIs that, when used incorrectly by the application developer, could introduce vulnerabilities in the application that allow arbitrary operations on the database. 

As Figure 2 shows, attackers can craft a Web access request with an injection that, when processed by the database client/protocol wrapper, will allow the desired illegal database operation.

![nosql injection](/images/nosql1.jpg)

Let's examine the architecture depicted in Figure 3, where a Web application is implemented with a PHP back end, which encodes the requests to the JSON format used to query the data store. Let's use a MongoDB example to show an array injection vulnerability—an attack similar to SQL injection in its technique and results.

![nosql injection](/images/nosql2.jpg)

PHP encodes arrays to JSON natively. So, for example, the array

{% highlight php %}
array(‘title’ => ‘The Hobbit’,   ‘author’ => ‘J.R.R. Tolkien’);
{% endhighlight %}

would be encoded by PHP to the following JSON:

{% highlight php %}
{“title”: “The Hobbit”, “author”:   “J.R.R. Tolkien”}
{% endhighlight %}

If a PHP application has a login mechanism in which the username and password are sent from the user's browser via HTTP POST (the vulnerability is applicable to HTTP get as well), a typical post URL–encoded payload would look like this:



{% highlight php %}
username=Tolkien&password=hobbit
{% endhighlight %}

The back-end PHP code to process it and query Mongo DB for the user would look like the following:



{% highlight php %}
db->logins->find(array(“username”=>$_   POST[“username”],   “password”=>$_POST[“password”]));
{% endhighlight %}

This makes perfect sense and is intuitively what the developer is likely to do, intending a query of



{% highlight php %}
db.logins.find({ username: ‘tolkien’,   password: ‘hobbit’})
{% endhighlight %}

However, PHP has a built-in mechanism for associative arrays that lets attackers send the following malicious payload:



{% highlight php %}
username[$ne]=1&password[$ne]=1
{% endhighlight %}

PHP translates this input into:



{% highlight php %}
array(“username” => array(“$[ne] “ =>   1), “password” =>   array(“$ne” => 1));,
{% endhighlight %}

which is encoded into the MongoDB query



{% highlight php %}
db.logins.find({ username: {$ne:1 },   password {$ne: 1 })
{% endhighlight %}

Because $ne is MongoDB's not equals condition, it queries all entries in the logins collection for which the username is not equal to 1 and the password is not equal to 1. Thus, this query will return all users in the logins collection. In SQL terminology, this is equivalent to:


{% highlight php %}
SELECT * FROM logins WHERE username <>   1 AND password <> 1
{% endhighlight %}


In this scenario, the vulnerability gives attackers a way to log in to the application without valid credentials. In other variants, the vulnerability might lead to illegal data access or privileged actions performed by an unprivileged user. To mitigate this issue, we need to cast the parameters received from the request to the proper type, in this case, using the string



{% highlight php %}
db->logins->find(  array(“username”=>(string)$_    POST[“username”],  “password”=>(string)$_    POST[“password”]));
{% endhighlight %}


# Prevention

if the attacker is able to have an object injected where a string is expected he can be able to forge a malicious MongoDB query.


- Manual Data validation
- Using a library


## PHP

### Example #1




{% highlight php %}
<?php
include_once 'parseTree.php';
use control\ParseTree;
	$stime=microtime(true);
   // connect to mongodb
   $m = new MongoClient();
//   echo "Connection to database successfully";
//	$postedusername = $_REQUEST['username'];
//	$postedpassword = $_REQUEST['password'];
	
   // select a database
   $db = $m->test;
//   echo "Database mydb selected";
   $collection = $db->users;
//   echo "Collection selected succsessfully";
   $dbUsername = null;
   $dbPassword = null;
   
 //   echo $postedusername;
 //  echo $postedpassword; 
   $data = array(
   		'username' =>  $_REQUEST['username'],
   		'password' =>  $_REQUEST['password']
   		
   ); 
   $cursor = $collection->find($data);
/*    $data = array(
   		'username' => array('$ne' => 1),
   		'password' => array('$ne' => 1)
   		 
   ); */
   $string = json_encode($data);
   echo $string;
   
//   print_r($data);
   $scope = array("user" => "Carl");
   $response = $db->execute("function(greeting, name) { return greeting+', '+name+'!'; }", array("Good bye", "Joe"));
   echo $response['retval'];
//   $db->execute("db.user.insert({'assdfdf':'dsaf'})");
 //  $response = $db->execute("db.user.find({'username':'sunuyang'})");
 //  print_r($response);
//   echo $response['retval'];
//    foreach ($data as $temp){
//    	echo $temp;
//    }
 //  $cursor = $collection->find($data);
   
   
   $count = $cursor->count();
   $doc_failed = new DOMDocument();
   $doc_failed->loadHTMLFile("failed.html");
   $doc_succeed = new DOMDocument();
   $doc_succeed->loadHTMLFile("succeed.html");
   $doc_attacked = new DOMDocument();
   $doc_attacked->loadHTMLFile("attacked.html");
//   echo $count;
   $parseTree = new ParseTree();
	if($parseTree->parseTree($string)){
		echo $doc_attacked->saveHTML();
	}
	else
	{
		if($count >0 ){
	
		//   	echo "<h1>login successed</h1>"."</br>";
		   	echo $doc_succeed->saveHTML();
		   	foreach ($cursor as $user){
		   			echo 'username:'.$user['username']."</br>";
		   			echo 'password:'.$user['password']."</br>";
		   		}
		   }
		   else{
		//   	echo "<h1>not find</h1>";
		   	echo $doc_failed->saveHTML();
		   }
	}
   $etime=microtime(true);
   $total=$etime-$stime;
   $str_total = var_export($total, TRUE);
   if(substr_count($str_total,"E")){
   	$float_total = floatval(substr($str_total,5));
   	$total = $float_total/100000;
   	echo $total.'seconds';
   } else echo $total.'seconds';
{% endhighlight %}

detected_login.php?username[$ne]=9a8942&password[$ne]=bf86om


### Example #2



{% highlight php %}
<?php
$stime=microtime(true);
$m = new MongoClient();
$db = $m->test;
$collection = $db->users;
  $query_body ="
		function q() {
			var username = ".$_REQUEST["username"].";
			var password = ".$_REQUEST["password"].";if(username == '1'&&password == '1') return true; else{ return false;}}
";  
  echo $query_body;
  //username=1&password=1;return true;}//
  
  
  
//$query_body = "function q() { var username = 1; var password = 1;return true;}//if(username == '1') 
//		return true;else{return false;}";
//echo $query_body;
$result = $collection->find(array('$where'=>$query_body));
$count = $result->count();
$doc_failed = new DOMDocument();
$doc_failed->loadHTMLFile("failed.html");
$doc_succeed = new DOMDocument();
$doc_succeed->loadHTMLFile("succeed.html");
if($count>0){
	echo $doc_succeed->saveHTML();
}
else{
//	echo "<h1>username or password is wrong!</h1>";
	echo $doc_failed->saveHTML();
}
$etime=microtime(true);
$total=$etime-$stime;
$str_total = var_export($total, TRUE);
if(substr_count($str_total,"E")){
	$float_total = floatval(substr($str_total,5));
	$total = $float_total/100000;
	echo $total.'seconds';
} else echo $total.'seconds';
{% endhighlight %}


login_1.php?username=1&password=2;var date = new Date(); var curDate = null; do { curDate = new Date(); } while((Math.abs(date.getTime()-curDate.getTime()))/100 < 20); return true;}//


## Solutions

### Method #1

use string type




{% highlight php %}
<?php
include_once 'parseTree.php';
use control\ParseTree;
	$stime=microtime(true);
   // connect to mongodb
   $m = new MongoClient();
//   echo "Connection to database successfully";
//	$postedusername = $_REQUEST['username'];
//	$postedpassword = $_REQUEST['password'];
	
   // select a database
   $db = $m->test;
//   echo "Database mydb selected";
   $collection = $db->users;
//   echo "Collection selected succsessfully";
   $dbUsername = null;
   $dbPassword = null;
   
 //   echo $postedusername;
 //  echo $postedpassword; 
   $data = array(
   		'username' =>  (string)$_REQUEST['username'],
   		'password' =>  (string)$_REQUEST['password']
   		
   ); 
   $cursor = $collection->find($data);
/*    $data = array(
   		'username' => array('$ne' => 1),
   		'password' => array('$ne' => 1)
   		 
   ); */
   $string = json_encode($data);
   echo $string;
   
//   print_r($data);
   $scope = array("user" => "Carl");
   $response = $db->execute("function(greeting, name) { return greeting+', '+name+'!'; }", array("Good bye", "Joe"));
   echo $response['retval'];
//   $db->execute("db.user.insert({'assdfdf':'dsaf'})");
 //  $response = $db->execute("db.user.find({'username':'sunuyang'})");
 //  print_r($response);
//   echo $response['retval'];
//    foreach ($data as $temp){
//    	echo $temp;
//    }
 //  $cursor = $collection->find($data);
   
   
   $count = $cursor->count();
   $doc_failed = new DOMDocument();
   $doc_failed->loadHTMLFile("failed.html");
   $doc_succeed = new DOMDocument();
   $doc_succeed->loadHTMLFile("succeed.html");
   $doc_attacked = new DOMDocument();
   $doc_attacked->loadHTMLFile("attacked.html");
//   echo $count;
   $parseTree = new ParseTree();
	if($parseTree->parseTree($string)){
		echo $doc_attacked->saveHTML();
	}
	else
	{
		if($count >0 ){
	
		//   	echo "<h1>login successed</h1>"."</br>";
		   	echo $doc_succeed->saveHTML();
		   	foreach ($cursor as $user){
		   			echo 'username:'.$user['username']."</br>";
		   			echo 'password:'.$user['password']."</br>";
		   		}
		   }
		   else{
		//   	echo "<h1>not find</h1>";
		   	echo $doc_failed->saveHTML();
		   }
	}
   $etime=microtime(true);
   $total=$etime-$stime;
   $str_total = var_export($total, TRUE);
   if(substr_count($str_total,"E")){
   	$float_total = floatval(substr($str_total,5));
   	$total = $float_total/100000;
   	echo $total.'seconds';
   } else echo $total.'seconds';
{% endhighlight %}

### Method #2


use addslashes function 




{% highlight php %}
<?php
$stime=microtime(true);
$m = new MongoClient();
$db = $m->test;
$collection = $db->users;
  $query_body ="
		function q() {
			var username = ".addslashes($_REQUEST["username"]).";
			var password = ".addslashes($_REQUEST["password"]).";if(username == '1'&&password == '1') return true; else{ return false;}}
";  
  echo $query_body;
  //username=1&password=1;return true;}//
  
  
  
//$query_body = "function q() { var username = 1; var password = 1;return true;}//if(username == '1') 
//		return true;else{return false;}";
//echo $query_body;
$result = $collection->find(array('$where'=>$query_body));
$count = $result->count();
$doc_failed = new DOMDocument();
$doc_failed->loadHTMLFile("failed.html");
$doc_succeed = new DOMDocument();
$doc_succeed->loadHTMLFile("succeed.html");
if($count>0){
	echo $doc_succeed->saveHTML();
}
else{
//	echo "<h1>username or password is wrong!</h1>";
	echo $doc_failed->saveHTML();
}
$etime=microtime(true);
$total=$etime-$stime;
$str_total = var_export($total, TRUE);
if(substr_count($str_total,"E")){
	$float_total = floatval(substr($str_total,5));
	$total = $float_total/100000;
	echo $total.'seconds';
} else echo $total.'seconds';
{% endhighlight %}

## ASP.NET


### Example #1



{% highlight c# %}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Couchbase;
using Couchbase.N1QL;

namespace N1QlInjection
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();

            ClusterHelper.Initialize();
        }

        private void btnWhereUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnCommentUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe' /* 21st century only */");
        }


        private void RunQuery(string query, IDictionary<string,object> parameters = null)
        {
            edtResults.Text = query + "\r\n\r\nRunning...";
            tabControl.Enabled = false;

            Task.Run(async () =>
            {
                var bucket = ClusterHelper.GetBucket("beer-sample");

                var queryRequest = new QueryRequest(query);
                
                if (parameters != null)
                {
                    queryRequest.AddNamedParameter(parameters.ToArray());
                };

                var result = await
                    bucket.QueryAsync<dynamic>(queryRequest);
                if (!result.Success)
                {
                    if (result.Errors != null && result.Errors.Count > 0)
                    {
                        return result.Errors.First().Message;
                    }
                    else if (result.Exception != null)
                    {
                        return string.Format("{0}\r\n\r\n{1}\r\n{2}", query, result.Exception.Message,
                            result.Exception.StackTrace);
                    }
                    else
                    {
                        return "Unknown Error";
                    }
                }
                else if (result.Rows != null)
                {
                    var sb = new StringBuilder();
                    sb.AppendFormat("{0}\r\n\r\n{1} rows returned\r\n\r\n", query, result.Rows.Count);

                    foreach (var row in result.Rows)
                    {
                        sb.AppendLine(row.ToString());
                    }

                    return sb.ToString();
                }
                else
                {
                    return query + "\r\n\r\n0 row returned";
                }
            })
                .ContinueWith(task =>
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (task.IsFaulted)
                        {
                            edtResults.Text = string.Format("{0}\r\n\r\n{1}\r\n{2}", query, task.Exception.Message,
                                task.Exception.StackTrace);
                        }
                        else
                        {
                            edtResults.Text = task.Result;
                        }

                        tabControl.Enabled = true;
                    }));
                });
        }
    }
}
{% endhighlight %}

### Example #2



{% highlight c# %}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Couchbase;
using Couchbase.N1QL;

namespace N1QlInjection
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();

            ClusterHelper.Initialize();
        }

        private void btnWhereUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnCommentUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe' /* 21st century only */");
        }

        private void btnIdentifierUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT " + edtIdentifier.Text + " FROM `beer-sample` " + 
                     "WHERE type = 'beer' AND brewery_id = '21st_amendment_brewery_cafe'");
        }


        private void RunQuery(string query, IDictionary<string,object> parameters = null)
        {
            edtResults.Text = query + "\r\n\r\nRunning...";
            tabControl.Enabled = false;

            Task.Run(async () =>
            {
                var bucket = ClusterHelper.GetBucket("beer-sample");

                var queryRequest = new QueryRequest(query);
                
                if (parameters != null)
                {
                    queryRequest.AddNamedParameter(parameters.ToArray());
                };

                var result = await
                    bucket.QueryAsync<dynamic>(queryRequest);
                if (!result.Success)
                {
                    if (result.Errors != null && result.Errors.Count > 0)
                    {
                        return result.Errors.First().Message;
                    }
                    else if (result.Exception != null)
                    {
                        return string.Format("{0}\r\n\r\n{1}\r\n{2}", query, result.Exception.Message,
                            result.Exception.StackTrace);
                    }
                    else
                    {
                        return "Unknown Error";
                    }
                }
                else if (result.Rows != null)
                {
                    var sb = new StringBuilder();
                    sb.AppendFormat("{0}\r\n\r\n{1} rows returned\r\n\r\n", query, result.Rows.Count);

                    foreach (var row in result.Rows)
                    {
                        sb.AppendLine(row.ToString());
                    }

                    return sb.ToString();
                }
                else
                {
                    return query + "\r\n\r\n0 row returned";
                }
            })
                .ContinueWith(task =>
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (task.IsFaulted)
                        {
                            edtResults.Text = string.Format("{0}\r\n\r\n{1}\r\n{2}", query, task.Exception.Message,
                                task.Exception.StackTrace);
                        }
                        else
                        {
                            edtResults.Text = task.Result;
                        }

                        tabControl.Enabled = true;
                    }));
                });
        }
    }
}
{% endhighlight %}

## Solutions

### Method #1



{% highlight c# %}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Couchbase;
using Couchbase.N1QL;

namespace N1QlInjection
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();

            ClusterHelper.Initialize();
        }

        private void btnWhereUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }
        
        private void btnWhereSafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text.Replace("'", "''") + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnWhereSafeParam_Click(object sender, EventArgs e)
        {
            var parameters = new Dictionary<string, object>()
            {
                { "$name", "%" + edtWhere.Text + "%" }
            };

            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE $name " +
                     "AND brewery_id = '21st_amendment_brewery_cafe'", parameters);

        }

        private void btnCommentUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe' /* 21st century only */");
        }
        
        private void btnCommentSafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text.Replace("'", "''") + "%' AND brewery_id = '21st_amendment_brewery_cafe'"); // 21st century only
        }

        private void RunQuery(string query, IDictionary<string,object> parameters = null)
        {
            edtResults.Text = query + "\r\n\r\nRunning...";
            tabControl.Enabled = false;

            Task.Run(async () =>
            {
                var bucket = ClusterHelper.GetBucket("beer-sample");

                var queryRequest = new QueryRequest(query);
                
                if (parameters != null)
                {
                    queryRequest.AddNamedParameter(parameters.ToArray());
                };

                var result = await
                    bucket.QueryAsync<dynamic>(queryRequest);
                if (!result.Success)
                {
                    if (result.Errors != null && result.Errors.Count > 0)
                    {
                        return result.Errors.First().Message;
                    }
                    else if (result.Exception != null)
                    {
                        return string.Format("{0}\r\n\r\n{1}\r\n{2}", query, result.Exception.Message,
                            result.Exception.StackTrace);
                    }
                    else
                    {
                        return "Unknown Error";
                    }
                }
                else if (result.Rows != null)
                {
                    var sb = new StringBuilder();
                    sb.AppendFormat("{0}\r\n\r\n{1} rows returned\r\n\r\n", query, result.Rows.Count);

                    foreach (var row in result.Rows)
                    {
                        sb.AppendLine(row.ToString());
                    }

                    return sb.ToString();
                }
                else
                {
                    return query + "\r\n\r\n0 row returned";
                }
            })
                .ContinueWith(task =>
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (task.IsFaulted)
                        {
                            edtResults.Text = string.Format("{0}\r\n\r\n{1}\r\n{2}", query, task.Exception.Message,
                                task.Exception.StackTrace);
                        }
                        else
                        {
                            edtResults.Text = task.Result;
                        }

                        tabControl.Enabled = true;
                    }));
                });
        }
    }
}
{% endhighlight %}

### Method #2



{% highlight c# %}
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Couchbase;
using Couchbase.N1QL;

namespace N1QlInjection
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();

            ClusterHelper.Initialize();
        }

        private void btnWhereUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnWhereSafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtWhere.Text.Replace("'", "''") + "%' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnWhereSafeParam_Click(object sender, EventArgs e)
        {
            var parameters = new Dictionary<string, object>()
            {
                { "$name", "%" + edtWhere.Text + "%" }
            };

            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE $name " +
                     "AND brewery_id = '21st_amendment_brewery_cafe'", parameters);

        }

        private void btnCommentUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text + "%' AND brewery_id = '21st_amendment_brewery_cafe' /* 21st century only */");
        }

        private void btnCommentSafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT * FROM `beer-sample` WHERE type = 'beer' AND name LIKE '%" +
                     edtComment.Text.Replace("'", "''") + "%' AND brewery_id = '21st_amendment_brewery_cafe'"); // 21st century only
        }

        private void btnIdentifierUnsafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT " + edtIdentifier.Text + " FROM `beer-sample` " + 
                     "WHERE type = 'beer' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void btnIdentifierSafe_Click(object sender, EventArgs e)
        {
            RunQuery("SELECT `" + edtIdentifier.Text.Replace("`", "``") + "` FROM `beer-sample` " +
                     "WHERE type = 'beer' AND brewery_id = '21st_amendment_brewery_cafe'");
        }

        private void RunQuery(string query, IDictionary<string,object> parameters = null)
        {
            edtResults.Text = query + "\r\n\r\nRunning...";
            tabControl.Enabled = false;

            Task.Run(async () =>
            {
                var bucket = ClusterHelper.GetBucket("beer-sample");

                var queryRequest = new QueryRequest(query);
                
                if (parameters != null)
                {
                    queryRequest.AddNamedParameter(parameters.ToArray());
                };

                var result = await
                    bucket.QueryAsync<dynamic>(queryRequest);
                if (!result.Success)
                {
                    if (result.Errors != null && result.Errors.Count > 0)
                    {
                        return result.Errors.First().Message;
                    }
                    else if (result.Exception != null)
                    {
                        return string.Format("{0}\r\n\r\n{1}\r\n{2}", query, result.Exception.Message,
                            result.Exception.StackTrace);
                    }
                    else
                    {
                        return "Unknown Error";
                    }
                }
                else if (result.Rows != null)
                {
                    var sb = new StringBuilder();
                    sb.AppendFormat("{0}\r\n\r\n{1} rows returned\r\n\r\n", query, result.Rows.Count);

                    foreach (var row in result.Rows)
                    {
                        sb.AppendLine(row.ToString());
                    }

                    return sb.ToString();
                }
                else
                {
                    return query + "\r\n\r\n0 row returned";
                }
            })
                .ContinueWith(task =>
                {
                    BeginInvoke(new Action(() =>
                    {
                        if (task.IsFaulted)
                        {
                            edtResults.Text = string.Format("{0}\r\n\r\n{1}\r\n{2}", query, task.Exception.Message,
                                task.Exception.StackTrace);
                        }
                        else
                        {
                            edtResults.Text = task.Result;
                        }

                        tabControl.Enabled = true;
                    }));
                });
        }
    }
}
{% endhighlight %}


## JAVA

### Example #1



{% highlight java %}
package nosql.injection.demo.model;

import com.mongodb.*;
import com.mongodb.util.JSON;

import java.net.UnknownHostException;

public class NoSQLDatabase {

    private DBCollection characters;

    private static NoSQLDatabase instance;

    public static NoSQLDatabase getInstance() throws UnknownHostException {
        if (instance == null) {
            instance = new NoSQLDatabase();
        }
        return instance;
    }

    public InjectionResult insecureFindByName(String name) throws UnknownHostException {

        InjectionResult injectionResult = new InjectionResult();

        String stringQuery = "{ 'name' : '" + name + "'}";
        injectionResult.setStringQuery(stringQuery);

        DBObject databaseQuery = (DBObject) JSON.parse(stringQuery);
        injectionResult.setDatabaseQuery(databaseQuery);

        DBCursor result = characters.find(databaseQuery);
        injectionResult.setResult(result);

        return injectionResult;
    }

    private NoSQLDatabase() throws UnknownHostException {

        // More details at http://docs.mongodb.org/ecosystem/tutorial/getting-started-with-java-driver/
        MongoClient mongoClient = new MongoClient();

        DB gameOfThronesDatabase = mongoClient.getDB("GameOfThrones");
        gameOfThronesDatabase.dropDatabase();

        characters = gameOfThronesDatabase.getCollection("characters");
        seedData();
    }

    private void seedData() {
        BasicDBObject robb = new BasicDBObject("_id", 1).append("name", "Robb").append("surname", "Stark").append("address", "Kingslayer");
        BasicDBObject sansa = new BasicDBObject("_id", 2).append("name", "Sansa").append("surname", "Stark").append("address", "Kingslayer");
        BasicDBObject tyrion = new BasicDBObject("_id", 3).append("name", "Tyrion").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject jaime = new BasicDBObject("_id", 4).append("name", "Jaime").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject cersei = new BasicDBObject("_id", 5).append("name", "Cersei").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject tywin = new BasicDBObject("_id", 6).append("name", "Tywin").append("surname", "Lannister").append("address", "Casterly Rock");
        characters.insert(robb);
        characters.insert(sansa);
        characters.insert(tyrion);
        characters.insert(jaime);
        characters.insert(cersei);
        characters.insert(tywin);
    }

}
{% endhighlight %}

## Solutions


### Method #1



{% highlight java %}
package nosql.injection.demo.model;

import com.mongodb.*;
import com.mongodb.util.JSON;

import java.net.UnknownHostException;

public class NoSQLDatabase {

    private DBCollection characters;

    private static NoSQLDatabase instance;

    public static NoSQLDatabase getInstance() throws UnknownHostException {
        if (instance == null) {
            instance = new NoSQLDatabase();
        }
        return instance;
    }

    public InjectionResult insecureFindByName(String name) throws UnknownHostException {

        InjectionResult injectionResult = new InjectionResult();

        String stringQuery = "{ 'name' : '" + name + "'}";
        injectionResult.setStringQuery(stringQuery);

        DBObject databaseQuery = (DBObject) JSON.parse(stringQuery);
        injectionResult.setDatabaseQuery(databaseQuery);

        DBCursor result = characters.find(databaseQuery);
        injectionResult.setResult(result);

        return injectionResult;
    }


    public InjectionResult secureFindByName(String name) throws UnknownHostException {

        InjectionResult injectionResult = new InjectionResult();

        BasicDBObject databaseQuery = new BasicDBObject("name", name);
        injectionResult.setDatabaseQuery(databaseQuery);

        DBCursor result = characters.find(databaseQuery);
        injectionResult.setResult(result);

        return injectionResult;
    }



    private NoSQLDatabase() throws UnknownHostException {

        // More details at http://docs.mongodb.org/ecosystem/tutorial/getting-started-with-java-driver/
        MongoClient mongoClient = new MongoClient();

        DB gameOfThronesDatabase = mongoClient.getDB("GameOfThrones");
        gameOfThronesDatabase.dropDatabase();

        characters = gameOfThronesDatabase.getCollection("characters");
        seedData();
    }

    private void seedData() {
        BasicDBObject robb = new BasicDBObject("_id", 1).append("name", "Robb").append("surname", "Stark").append("address", "Kingslayer");
        BasicDBObject sansa = new BasicDBObject("_id", 2).append("name", "Sansa").append("surname", "Stark").append("address", "Kingslayer");
        BasicDBObject tyrion = new BasicDBObject("_id", 3).append("name", "Tyrion").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject jaime = new BasicDBObject("_id", 4).append("name", "Jaime").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject cersei = new BasicDBObject("_id", 5).append("name", "Cersei").append("surname", "Lannister").append("address", "Casterly Rock");
        BasicDBObject tywin = new BasicDBObject("_id", 6).append("name", "Tywin").append("surname", "Lannister").append("address", "Casterly Rock");
        characters.insert(robb);
        characters.insert(sansa);
        characters.insert(tyrion);
        characters.insert(jaime);
        characters.insert(cersei);
        characters.insert(tywin);
    }

}
{% endhighlight %}


