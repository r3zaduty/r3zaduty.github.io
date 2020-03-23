---
layout: post
title:  "XML Injection Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net xml injection
description: XML Injection Prevention in php, asp.net and java
---
# What is XML injection ?

XML or SOAP injection vulnerabilities arise when user input is inserted into a server-side XML document or SOAP message in an unsafe way. It may be possible to use XML metacharacters to modify the structure of the resulting XML. Depending on the function in which the XML is used, it may be possible to interfere with the application's logic, to perform unauthorized actions or access sensitive data.

This kind of vulnerability can be difficult to detect and exploit remotely; you should review the application's response, and the purpose that the relevant input performs within the application's functionality, to determine whether it is indeed vulnerable.

Let's suppose there is a web application using an XML style communication in order to perform user registration. 

This is done by creating and adding a new <user> node in an xmlDb file.

Let's suppose the xmlDB file is like the following:


{% highlight xml %}
<?xml version="1.0" encoding="ISO-8859-1"?> 
<users> 
	<user> 
		<username>gandalf</username> 
		<password>!c3</password> 
		<userid>0</userid>
		<mail>gandalf@middleearth.com</mail>
	</user> 
	<user> 
		<username>Stefan0</username> 
		<password>w1s3c</password> 
		<userid>500</userid>
		<mail>Stefan0@whysec.hmm</mail>
	</user> 
</users>
{% endhighlight %}

When a user registers himself by filling an HTML form, the application receives the user's data in a standard request, which, for the sake of simplicity, will be supposed to be sent as a GET request.


For example, the following values:



{% highlight php %}
Username: tony
Password: Un6R34kb!e
E-mail: s4tan@hell.com
{% endhighlight %}

will produce the request:



{% highlight php %}
http://www.example.com/addUser.php?username=tony&password=Un6R34kb!e&email=s4tan@hell.com
{% endhighlight %}


The application, then, builds the following node:



{% highlight xml %}
<user> 
	<username>tony</username> 
	<password>Un6R34kb!e</password> 
	<userid>500</userid>
	<mail>s4tan@hell.com</mail>
</user>
{% endhighlight %}

which will be added to the xmlDB:



{% highlight xml %}
<?xml version="1.0" encoding="ISO-8859-1"?> 
<users> 
	<user> 
		<username>gandalf</username> 
		<password>!c3</password> 
		<userid>0</userid>
		<mail>gandalf@middleearth.com</mail>
	</user> 
	<user> 
		<username>Stefan0</username> 
		<password>w1s3c</password> 
		<userid>500</userid>
		<mail>Stefan0@whysec.hmm</mail>
	</user> 
	<user> 
		<username>tony</username> 
		<password>Un6R34kb!e</password> 
		<userid>500</userid>
		<mail>s4tan@hell.com</mail>
	</user> 
</users>
{% endhighlight %}

# Prevention

The injections we referred to in the last article are based on object injection: if the attacker is able to have an object injected where a string is expected he can be able to forge a malicious MongoDB query.


- Manual Data validation
- Using a library

## PHP

### Example #1


<test>example</test>



{% highlight php %}
<!DOCTYPE html>
<html lang="en">


	<head>

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

		<title>XML Bomb Denial-of-Service</title>

		<?php require(dirname(__FILE__)."../../../bootstrap.php") ?>

	</head>
	 <body>


		 <!-- Sidebar -->
	 <div id="wrapper">

		 <div class="col-md-3">
		 <?php require(dirname(__FILE__)."../../../sidebar.php") ?>
	</div>

			<div id="page-content-wrapper">
						<div class="container-fluid">
								<div class="row">
										<div class="col-lg-12">


    </html>
<?php
	$simple = $_POST['name'];
	$p = xml_parser_create();
	xml_parse_into_struct($p, $simple, $vals, $index);
	xml_parser_free($p);
	echo "<br><br>The following array was created from your XML data\n <br><br>";
	print_r($index);
	echo "\nVals array\n";
	print_r($vals);
	 get_server_memory_usage();
	 get_server_cpu_usage();
function get_server_memory_usage(){
    //shows server memory usage
    if (stristr(PHP_OS, 'Linux'))
    {
		$free = shell_exec('free');
		$free = (string)trim($free);
		$free_arr = explode("\n", $free);
		$mem = explode(" ", $free_arr[1]);
		$mem = array_filter($mem);
		$mem = array_merge($mem);
		$memory_usage = $mem[2]/$mem[1]*100;
		print "<br><br><br> The server memory usage is ".$memory_usage;
	}
	else
	{
	$cmd = 'typeperf  -sc 1  "\Processor(_Total)\% Processor Time"';
	exec($cmd, $lines, $retval);
	if($retval == 0) {
		$values = str_getcsv($lines[2]);
		print "<br><br><br> The server memory usage is ".floatval($values[1]);
	} else {
		return false;
	}
	}
}
function get_server_cpu_usage(){
    //shows server CPU Usage
{
    $load=array();
    if (stristr(PHP_OS, 'win'))
    {
    $output = array();
    exec( 'tasklist ', $output );
    foreach ($output as $value)
    {
        $ex=explode(" ",$value);
        $count_ex=count($ex);
        if (eregi(" ".getmypid()." Console",$value))
        {
            $memory_size=$ex[$count_ex-2]." Kb";
            print "<br><br>The server CPU usage is ".$memory_size;
        }
    }
    }
    else
    {
        $load = sys_getloadavg();
        print "<br><br>The server CPU usage is ".$load[0];
    }
    return $load;
}
}
?>
{% endhighlight %}

## Solution


### Method #1


with addslashes function



{% highlight php %}
<!DOCTYPE html>
<html lang="en">


	<head>

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

		<title>XML Bomb Denial-of-Service</title>

		<?php require(dirname(__FILE__)."../../../bootstrap.php") ?>

	</head>
	 <body>


		 <!-- Sidebar -->
	 <div id="wrapper">

		 <div class="col-md-3">
		 <?php require(dirname(__FILE__)."../../../sidebar.php") ?>
	</div>

			<div id="page-content-wrapper">
						<div class="container-fluid">
								<div class="row">
										<div class="col-lg-12">


    </html>
<?php
	$simple = addslashes($_POST['name']);
	$p = xml_parser_create();
	xml_parse_into_struct($p, $simple, $vals, $index);
	xml_parser_free($p);
	echo "<br><br>The following array was created from your XML data\n <br><br>";
	print_r($index);
	echo "\nVals array\n";
	print_r($vals);
	 get_server_memory_usage();
	 get_server_cpu_usage();
function get_server_memory_usage(){
    //shows server memory usage
    if (stristr(PHP_OS, 'Linux'))
    {
		$free = shell_exec('free');
		$free = (string)trim($free);
		$free_arr = explode("\n", $free);
		$mem = explode(" ", $free_arr[1]);
		$mem = array_filter($mem);
		$mem = array_merge($mem);
		$memory_usage = $mem[2]/$mem[1]*100;
		print "<br><br><br> The server memory usage is ".$memory_usage;
	}
	else
	{
	$cmd = 'typeperf  -sc 1  "\Processor(_Total)\% Processor Time"';
	exec($cmd, $lines, $retval);
	if($retval == 0) {
		$values = str_getcsv($lines[2]);
		print "<br><br><br> The server memory usage is ".floatval($values[1]);
	} else {
		return false;
	}
	}
}
function get_server_cpu_usage(){
    //shows server CPU Usage
{
    $load=array();
    if (stristr(PHP_OS, 'win'))
    {
    $output = array();
    exec( 'tasklist ', $output );
    foreach ($output as $value)
    {
        $ex=explode(" ",$value);
        $count_ex=count($ex);
        if (eregi(" ".getmypid()." Console",$value))
        {
            $memory_size=$ex[$count_ex-2]." Kb";
            print "<br><br>The server CPU usage is ".$memory_size;
        }
    }
    }
    else
    {
        $load = sys_getloadavg();
        print "<br><br>The server CPU usage is ".$load[0];
    }
    return $load;
}
}
?>
{% endhighlight %}

## ASP.NET


### Example #1



{% highlight c# %}
XmlDocument doc = new XmlDocument();
doc.LoadXml(template);
XmlElement list = doc.CreateElement(conn.XmlListTagName);
foreach (EaiItem updateItem in itemList)
{
    XmlElement item = doc.CreateElement( conn.XmlItemTagName );
    foreach(String itemAttrib in updateItem.ItemAttributes.Keys)
    {
        item.SetAttribute(itemAttrib, updateItem.ItemAttributes[itemAttrib]);
    }
    item.InnerXml = updateItem.ItemFieldXml;
    list.AppendChild(item);
}
doc.LastChild.AppendChild(list);
{% endhighlight %}

## Solution

### Method #1



{% highlight c# %}
XmlDocument doc = new XmlDocument();
doc.LoadXml(template);
XmlElement list = doc.CreateElement(conn.XmlListTagName);
foreach (EaiItem updateItem in itemList)
{
    XmlElement item = doc.CreateElement( conn.XmlItemTagName );
    foreach(String itemAttrib in updateItem.ItemAttributes.Keys)
    {
        item.SetAttribute(itemAttrib, updateItem.ItemAttributes[itemAttrib]);
    }
    item.InnerText = updateItem.ItemFieldXml;
    list.AppendChild(item);
}
doc.LastChild.AppendChild(list);
{% endhighlight %}

## JAVA

### Example #1



{% highlight java %}
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
 
public class OnlineStore {
  private static void createXMLStreamBad(final BufferedOutputStream outStream,
      final String quantity) throws IOException {
    String xmlString = "<item>\n<description>Widget</description>\n"
        + "<price>500</price>\n" + "<quantity>" + quantity
        + "</quantity></item>";
    outStream.write(xmlString.getBytes());
    outStream.flush();
  }
}
{% endhighlight %}

## Solutions

### Method #1



{% highlight java %}
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
 
public class OnlineStore {
  private static void createXMLStream(final BufferedOutputStream outStream,
      final String quantity) throws IOException, NumberFormatException {
    // Write XML string only if quantity is an unsigned integer (count).
    int count = Integer.parseUnsignedInt(quantity);
    String xmlString = "<item>\n<description>Widget</description>\n"
        + "<price>500</price>\n" + "<quantity>" + count + "</quantity></item>";
    outStream.write(xmlString.getBytes());
    outStream.flush();
  }
}
{% endhighlight %}


### Method #2


general mechanism for checking XML for attempted injection is to validate it using a Document Type Definition (DTD) or schema. The schema must be rigidly defined to prevent injections from being mistaken for valid XML. Here is a suitable schema for validating our XML snippet:



{% highlight xml %}
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
<xs:element name="item">
  <xs:complexType>
    <xs:sequence>
      <xs:element name="description" type="xs:string"/>
      <xs:element name="price" type="xs:decimal"/>
      <xs:element name="quantity" type="xs:nonNegativeInteger"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
</xs:schema>
{% endhighlight %}

The schema is available as the file schema.xsd. This compliant solution employs this schema to prevent XML injection from succeeding.



{% highlight java %}
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
 
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
 
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
 
public class OnlineStore {
 
  private static void createXMLStream(final BufferedOutputStream outStream,
      final String quantity) throws IOException {
    String xmlString;
    xmlString = "<item>\n<description>Widget</description>\n"
        + "<price>500.0</price>\n" + "<quantity>" + quantity
        + "</quantity></item>";
    InputSource xmlStream = new InputSource(new StringReader(xmlString));
    // Build a validating SAX parser using our schema
    SchemaFactory sf = SchemaFactory
        .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    DefaultHandler defHandler = new DefaultHandler() {
      public void warning(SAXParseException s) throws SAXParseException {
        throw s;
      }
      public void error(SAXParseException s) throws SAXParseException {
        throw s;
      }
      public void fatalError(SAXParseException s) throws SAXParseException {
        throw s;
      }
    };
    StreamSource ss = new StreamSource(new File("schema.xsd"));
    try {
      Schema schema = sf.newSchema(ss);
      SAXParserFactory spf = SAXParserFactory.newInstance();
      spf.setSchema(schema);
      SAXParser saxParser = spf.newSAXParser();
      // To set the custom entity resolver,
      // an XML reader needs to be created
      XMLReader reader = saxParser.getXMLReader();
      reader.setEntityResolver(new CustomResolver());
      saxParser.parse(xmlStream, defHandler);
    } catch (ParserConfigurationException x) {
      throw new IOException("Unable to validate XML", x);
    } catch (SAXException x) {
      throw new IOException("Invalid quantity", x);
    }
    // Our XML is valid, proceed
    outStream.write(xmlString.getBytes());
    outStream.flush();
  }
}
{% endhighlight %}


