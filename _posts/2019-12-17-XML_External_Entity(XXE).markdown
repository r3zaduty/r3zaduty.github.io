---
layout: post
title:  "XML External Entity (XXE) Prevention(PHP,ASP.NET,JAVA)"
date:   2019-12-17 20:17:31 1576601251
categories: securec0ding
tags: php java asp.net xml
description: XML External Entity (XXE) Prevention in php, asp.net and java
---
# What is XML External Entity (XXE) ?

XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.


![sql injection](/images/xxe.png)

o perform an XXE injection attack that retrieves an arbitrary file from the server's filesystem, you need to modify the submitted XML in two ways:


- Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to the file.
- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:


{% highlight xml %}
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
{% endhighlight %}

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:



{% highlight xml %}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
{% endhighlight %}

This XXE payload defines an external entity &xxe; whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:



{% highlight php %}
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
{% endhighlight %}

# Prevention

## PHP

### Example #1



{% highlight php %}
<?php 
$goodXML = '<test><testing>my value</testing></test>'; 
$badXml = '<!DOCTYPE root [ <!ENTITY foo SYSTEM "http://test.localhost:8080/contents.txt"> ]> <test><testing>&foo;</testing></test>';
$doc = simplexml_load_string($badXml ); 
echo $doc->testing; 
?>
{% endhighlight %}

### Example #2



{% highlight php %}
// In XML processors based on libxml2, dangerous LIBXML constants include: LIBXML_DTDLOAD, LIBXML_DTDVALID, LIBXML_NOENT, LIBXML_XINCLUDE

$xml = $_GET["xml"];

$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT); // Noncompliant

$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT); // Noncompliant

$reader = new XMLReader();
$reader->XML($xml, NULL, LIBXML_NOENT); // Noncompliant
{% endhighlight %}

## Solutions

### Method #1



{% highlight php %}
<?php 
$goodXML = '<test><testing>my value</testing></test>'; 
$badXml = '<!DOCTYPE root [ <!ENTITY foo SYSTEM "http://test.localhost:8080/contents.txt"> ]> <test><testing>&foo;</testing></test>';
libxml_disable_entity_loader(true);
$doc = simplexml_load_string($badXml); 
echo $doc->testing; 
?>
{% endhighlight %}

### Method #2



{% highlight php %}
// Starting with libxml2 version 2.9, dangerous functionality is disabled by default

$xml = $_GET["xml"];

$doc = simplexml_load_string($xml);

$doc = new DOMDocument();
$doc->loadXML($xml);

$reader = new XMLReader();
$reader->XML($xml);
{% endhighlight %}

## ASP.NET


### Example #1



{% highlight c# %}
StreamReader stream = new StreamReader(data);
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;
XmlReader xmlReader = XmlReader.Create(stream, settings);
{% endhighlight %}

## Solution

### Method #1


{% highlight c# %}
StreamReader stream = new StreamReader(data);
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Ignore;
XmlReader xmlReader = XmlReader.Create(stream, settings);
{% endhighlight %}

## JAVA

### Example #1



{% highlight java %}
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
 
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
 
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
 
class XXE {
  private static void receiveXMLStream(InputStream inStream,
                                       DefaultHandler defaultHandler)
      throws ParserConfigurationException, SAXException, IOException {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    SAXParser saxParser = factory.newSAXParser();
    saxParser.parse(inStream, defaultHandler);
  }
 
  public static void main(String[] args) throws ParserConfigurationException,
      SAXException, IOException {
    try {
      receiveXMLStream(new FileInputStream("evil.xml"), new DefaultHandler());
    } catch (java.net.MalformedURLException mue) {
      System.err.println("Malformed URL Exception: " + mue);
    }
  }
}
{% endhighlight %}

## Solution

### Method #1



{% highlight java %}
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
 
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
 
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
 
class XXE {
  private static void receiveXMLStream(InputStream inStream,
      DefaultHandler defaultHandler) throws ParserConfigurationException,
      SAXException, IOException {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    SAXParser saxParser = factory.newSAXParser();
 
    // Create an XML reader to set the entity resolver.
    XMLReader reader = saxParser.getXMLReader();
    reader.setEntityResolver(new CustomResolver());
    reader.setContentHandler(defaultHandler);
 
    InputSource is = new InputSource(inStream);
    reader.parse(is);
  }
 
  public static void main(String[] args) throws ParserConfigurationException,
      SAXException, IOException {
    try {
      receiveXMLStream(new FileInputStream("evil.xml"), new DefaultHandler());
    } catch (java.net.MalformedURLException mue) {
      System.err.println("Malformed URL Exception: " + mue);
    }
  }
}
{% endhighlight %}
