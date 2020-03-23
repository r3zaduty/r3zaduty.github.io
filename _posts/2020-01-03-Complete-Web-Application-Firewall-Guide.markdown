---
layout: post
title:  "Complete Web Application Firewall Guide"
date:   2020-01-03 00:01:01 1576601251
categories: web
tags: waf,web,application,firewall
description: A WAF or Web Application Firewall helps protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet.
---
# What is a Web Application Firewall (WAF)?


A WAF or Web Application Firewall helps protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet.

It typically protects web applications from attacks such as cross-site forgery, cross-site-scripting (XSS), file inclusion, and SQL injection, among others. A WAF is a protocol layer 7 defense (in the OSI model), and is not designed to defend against all types of attacks.

This method of attack mitigation is usually part of a suite of tools which together create a holistic defense against a range of attack vectors.

![mlytics](/images/mlytics.jpeg)

By deploying a WAF in front of a web application, a shield is placed between the web application and the Internet.


While a proxy server protects a client machine’s identity by using an intermediary, a WAF is a type of reverse-proxy, protecting the server from exposure by having clients pass through the WAF before reaching the server.


A WAF operates through a set of rules often called policies. These policies aim to protect against vulnerabilities in the application by filtering out malicious traffic.


The value of a WAF comes in part from the speed and ease with which policy modification can be implemented, allowing for faster response to varying attack vectors; during a DDoS attack, rate limiting can be quickly implemented by modifying WAF policies.


![Mobisoft Infotech](/images/MobisoftInfotech.png)

# What is the difference between blacklist and whitelist WAFs?


A WAF that operates based on a blacklist (negative security model) protects against known attacks.


Think of a blacklist WAF as a club bouncer instructed to deny admittance to guests who don’t meet the dress code.


Conversely, a WAF based on a whitelist (positive security model) only admits traffic that has been pre-approved. This is like the bouncer at an exclusive party, he or she only admits people who are on the list.


Both blacklists and whitelists have their advantages and drawbacks, which is why many WAFs offer a hybrid security model, which implements both.


# What are network-based, host-based, and cloud-based WAFs?


A WAF can be implemented one of three different ways, each with it’s own benefits and shortcomings:

1- A network-based WAF is generally hardware-based: since they are installed locally they minimize latency, but network-based WAFs are the most expensive option and also require the storage and maintenance of physical equipment.
2- A host-based WAF may be fully integrated into an application’s software: This solution is less expensive than a network-based WAF and offers more customizability. The downside of a host-based WAF is the consumption of local server resources, implementation complexity, and maintenance costs. These components typically require engineering time, and may be costly.
3- Cloud-based WAFs offer an affordable option that is very easy to implement: they usually offer a turnkey installation that is as simple as a change in DNS to redirect traffic. Cloud-based WAFs also have a minimal upfront cost, as users pay monthly or annually for security as a service. Cloud-based WAFs can also offer a solution that is consistently updated to protect against the newest threats without any additional work or cost on the user’s end. The drawback of a cloud-based WAF is that users hand over the responsibility to a third-party, therefore some features of the WAF may be a black box to them. Learn about Cloudflare’s cloud-based WAF solution.


# Software WAF vs. Appliance WAF

![applicure.com](/images/applicurecom.png)

# Web Application Firewall Deployment


## Reverse Proxy


The WAF is a proxy to the application server. Therefore, device traffic goes directly to the WAF.


##Transparent Reverse Proxy


A reverse proxy with transparent mode. As a result, the WAF separately sends filtered traffic to web applications.


This allows for IP masking by hiding the address of the application server. Performance latency is a potential downside during translation.


## Transparent Bridge

As a result, this makes the WAF transparent between the device and the server.


# Cloud WAF vs On-Premises WAF


There are two main varieties of Web Application Firewall solutions — on-premise WAF (aka Hardware WAF) or cloud WAF.


Deciding which is best for your enterprise depends entirely on your needs.


Cloud WAFs, provided via SaaS, are managed by your cloud vendor: hardware or software, updates, and security are all maintained by your chosen provider and accessed through a mobile app or web interface.


A high compute capacity makes cloud WAFs more efficient than their hardware counterparts at detection of attacks (DDoS), deep security insights with real-time monitoring, and minimization of false positives with advanced analytics.


With simple point-and-click configuration, cloud WAFs grow with you, scaling to your capacity needs on a flexible, responsive platform. Comprehensive, high performance security helps meet compliance requirements like GDPR, PCI DSS, and HIPAA.


Typically, a usage-based payment plan for a web application security firewall is arranged in advance.


On-Premises hardware WAFs require far more legwork for security and IT teams, but can provide more fine-tuning customization.


Where cloud software is stored and managed in the provider’s high security data center, your administrators will need to dedicate an in-house team to secure your network.


The procurement and installment of hardware or software, maintenance, configuration, and updates are usually the technical team’s responsibility.


Estimating capacity with hardware WAFs may result in either an excess of or deficient security, depending on fluctuating traffic. Scaling to meet capacity needs will require further WAF hardware adjustments.


Having full access to all of the elements of your platform may be the right plan for your enterprise, allowing you full reign to customize the experience to your unique specifications.


# How WAFs Work:

1- Using a set of rules to distinguish between normal requests and malicious requests;
2- Sometimes they use a learning mode to add rules automatically through learning about user behaviour

## Operation Modes:

1- Negative Model (Blacklist based) — A blacklisting model uses pre-set signatures to block web traffic that is clearly malicious, and signatures designed to prevent attacks which exploit certain website and web application vulnerabilities. Blacklisting model web application firewalls are a great choice for websites and web applications on the public internet, and are highly effective against an major types of DDoS attacks. Eg. Rule for blocking all <script>*</script> inputs.
2- Positive Model (Whitelist based) — A whitelisting model only allows web traffic according to specifically configured criteria. For example, it can be configured to only allow HTTP GET requests from certain IP addresses. This model can be very effective for blocking possible cyber-attacks, but whitelisting will block a lot of legitimate traffic. Whitelisting model firewalls are probably best for web applications on an internal network that are designed to be used by only a limited group of people, such as employees.
3- Mixed/Hybrid Model (Inclusive model) — A hybrid security model is one that blends both whitelisting and blacklisting. Depending on all sorts of configuration specifics, hybrid firewalls could be the best choice for both web applications on internal networks and web applications on the public internet.


## Detection Techniques:

To identify WAFs, we need to (dummy) provoke it.

1- Make a normal GET request from a browser, intercept and record response headers (specifically cookies).
2- Make a request from command line (eg. cURL), and test response content and headers (no user-agent included).
3- Make GET requests to random open ports and grab banners which might expose the WAFs identity.
4- If there is a login page somewhere, try some common (easily detectable) payloads like " or 1 = 1 --.
5- If there is some input field somewhere, try with noisy payloads like `<script>alert()</script>`.
6- Attach a dummy ../../../etc/passwd to a random parameter at end of URL.
7- Append some catchy keywords like ' OR SLEEP(5) OR ' at end of URLs to any random parameter.
8- Make GET requests with outdated protocols like HTTP/0.9 (HTTP/0.9 does not support POST type queries).
9- Many a times, the WAF varies the Server header upon different types of interactions.
10- Drop Action Technique — Send a raw crafted FIN/RST packet to server and identify response.

Tip: This method could be easily achieved with tools like HPing3 or Scapy.

# Resource

1-https://medium.com/schkn/web-application-firewall-guide-125645343beb



