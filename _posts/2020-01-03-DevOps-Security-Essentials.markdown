---
layout: post
title:  "DevOps Security Essentials
"
date:   2020-01-03 00:02:01 1576601251
categories: network
tags: network,dev,sec,ops,devsecops
description: DevOps is a cultural and professional movement, focused on how we build and operate high velocity organizations, born from the experiences of its practitioners.
---

# Definition of DevOps

DevOps is a cultural and professional movement, focused on how we build and operate high velocity organizations, born from the experiences of its practitioners
- Nathan Harvey


![veracode](/images/1_u48eHBzDwrfsx7q7JrYQWQ.png)

Organizations across the world are excited to make a cultural change or shift and adapt to DevOps as early as possible.


While everybody is just talking about how fast they can practice this approach, they forget about the security aspect involved with this change.


DevOps might initially involve that needed change in the culture, but as it embeds across the organization, it requires more scrutiny at each phase and has to be taken seriously.


Shifting security to the left can help organizations to be more secure and do well in the future.

![veracode](/images/veracode.png)

The customer is the king, and the market has numerous alternatives these days, more choices and more power to consumers.


The ultimate goal of any firm whether product/service based should be to deliver quality and continuously make sure the customer info/data is secure.


In the software development field, the Continuous Delivery of software is supported by build and deployment automation commonly called a Continuous Integration/Continuous Deployment (CICD) pipeline.


The CICD pipeline makes it possible to employ rapid changes daily to address customer needs and demands. The CI/CD pipeline can be automated as well, and hence Security has to be a design constraint these days.


Thinking security right from the beginning requires security to be built into software instead of being bolted on.


*****Security is no more an add-on.*****

# DevOps Security Challenges and Considerations

![opcito.com](/images/opcitocom.jpg)


* DevOps’ focus on speed often leaves security teams flat-footed and reactive


DevOps teams are frequently malaligned with Infosec teams. DevOps pushes and modifies batches of code over very short time frames (hours or days), which may far outpace the speed at which security teams can keep up with code review.

If security (configuration checks, code analysis, vulnerability scanning, etc.) is not adequately automated, the DevOps output will either be dramatically slowed, or lack proper security hygiene. In practice, the fallout from this misalignment includes insecure code, inadvertent vulnerabilities, misconfigurations, hardcoded passwords, and other weakness in application security that can be exploited by attackers, or contribute to operational dysfunction, including downtime.


* Cultural resistance to security


There’s a widespread perception that introducing security will slow or derail the development process. However, the time and effort cost of catching a security flaw early in the design and development process is much lower than having to retroactively fix problematic code and weaknesses later in the development cycle.


* DevOps and cloud environments


The typical DevOps environment relies on cloud deployments, thereby sharing many cloud security considerations. DevOps teams often leverage new, open-source or immature tools to manage hundreds of security groups and thousands of server instances.


In these fast-moving environments that operate at tremendous scale, a simple misconfiguration error or security malpractice, such as sharing of secrets (APIs, privileged credentials, SSH keys, etc.) can be broadly propagated, causing widespread operational dysfunction, or numerous exploitable security and/or compliance issues.


* Containers and other tools carry their own risks


The ascension of containers and the tools to manage them (Docker, Kubernetes, CoreOs etc.) across DevOps environments confers exceptional productivity and innovation potential for users, while at the same time spawning new security headaches.


First, consider the security implications of the containers themselves. As an ultra-lightweight and portable packaging platform for applications, containers can be spun up and down almost instantly — and run across almost any kind of computer and cloud. However, without proper controls in place, containers can pose security risks due to lack of visibility into the containers themselves, which is complicated because they share an OS with other containers.


Frequently, containers are not adequately scanned for vulnerabilities. A study by ThreatStack underscored this, with an alarming 94% of respondents indicating that containers pose negative security implications for their organizations.


* Unmanaged secrets and poor privileged access controls open dangerous backdoors


Most facets of DevOps are highly interconnected, rapidly changing, and utilize secrets. DevOps secrets may include privileged account credentials, SSH Keys, APIs tokens, etc., and may be used by humans or non-humans (e.g., applications, containers, micro-services and cloud instances).


Inadequate secrets management is a common shortcoming of DevOps environments, providing a tantalizing avenue for attackers to tamper with security and other controls, disrupt operations, steal information, and basically own an organization’s IT infrastructure. A typical DevOps environment may leverage several dozen tools (Chef, Puppet, Ansible, Salt, etc.) that all require secrets management.


Additionally, to help expedite workflows, DevOps teams may allow almost unrestricted access to privileged accounts (root, admin, etc.), by multiple individuals, who may share credentials — a practice that virtually eliminates the possibility of a clean audit trail.


Various orchestration, configuration management, and other DevOps tools may also be granted vast privileges. With privileged access rights in hand, a hacker or piece of malware can gain full control of the systems and data, so it’s essential for organizations to rein in excessive privilege rights and access.


* Uber Delivers a Cautionary Lesson for the DevOps Culture


It’s arguable what was more egregious about Uber’s breach of information of 57 million customers as well as roughly 600,000 drivers; the fact that Uber paid hackers hush money to conceal the hack from the public for months, or the reckless disregard for proper security that led to the hack.


As we’ve discussed, in DevOps environments, the need for speed may lead to risky shortcut-taking. In this instance, an Uber employee published credentials on GitHub, a popular cloud-based, open-source code repository used by developers. A hacker simply captured the Uber credentials off GitHub, then leveraged them for privileged access on Uber’s Amazon AWS Instances. As inexcusable (or at least as inadvisable) as this practice sounds, developers commonly embed authentication credentials and other DevOps secrets haphazardly into code for easy access.


Unfortunately, hackers have this figured out, know where to look, and prey on negligence.


# DevOps Process: Where is security?


![veracode](/images/1_mLn-VOFSSE7MaDbIx1EUJg.png)

DevOps security refers to the discipline and practice of safeguarding the entire DevOps environment through strategies, policies, processes, and technology. Security should be built into every part of the DevOps lifecycle, including inception, design, build, test, release, support, maintenance, and beyond.


# Strategy

1- Integration & Automation
2- 3-legged barstool:
– Training
Security teams can help developers by providing training, either through eLearning or in-person Instructor Led Training
Think about targeted training based on policy violations
– Remediation Coaching
For applications that used remediation coaching, development teams fixed more than 2.5x the average # of flaws per megabyte
– Scan early & often
Applications that used sandbox had an average fix rate of 59%, or a 2x improvement in fix rate


## Strategy –Integration & Automation


![veracode](/images/1_K3IkFzBEyUOd50ehlWajwQ.png)


A *moment* in the life of a feature


![@dschleen](/images/1_Xv0ymuh0Wwnssi7Pk8RQ8w.png)


# DevOps –Pervasive Security

![veracode](/images/1_9kKTnHd4O9aSsgiOMXDqbg.png)


# DevOps Security Checklist

## Culture

1- Cover your ass
2- Follow an onboarding / offboarding checklist
3- Gamify security and train employees on a regular basis
4- Stay on top of best practices
5- Understand the risk

## Code

1- Don’t implement your own crypto
2- Ensure you are using security headers
3- Go hack yourself
4- Integrate security scanners in your CI pipeline
5- Keep your dependencies up to date
6- Protect your CI/CD tools like your product
7- Run Security tests on your code


## Infrastructure

1- Automatically configure & update your servers
2- Backup regularly
3- Check your SSL / TLS configurations
4- Control access on your cloud providers
5- Encrypt all the things
6- Harden SSH configurations
7- Keep your containers protected
8- Log all the things
9- Manage secrets with dedicated tools and vaults
10- Store encrypted passwords in your configuration management
11- Upgrade your servers regularly
12- Use an immutable infrastructure


## Protection

1- Don’t store credit card information (if you don’t need to)
2- Enforce Two-Factor Authentication (2FA)
3- Ensure Compliance with Relevant Industry Standards
4- Have a public bug bounty program
5- Have a public security policy
6- Protect against Denial Of Service (DoS)
7- Protect your applications against breaches
8- Protect your servers and infrastructure
9- Protect your users against account takeovers


## Monitoring

1- Audit your infrastructure on a regular basis
2- Check that TLS certificates are not set to expire
3- Detect insider threats
4- Get notified when your app is under attack
5- Monitor third party vendors
6- Monitor your authorizations
7- Monitor your DNS expiration date


# Resources

https://medium.com/schkn/devops-security-99face898f52

