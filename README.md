## Contents

- [Disk Image Creation Tools](#disk-image-creation-tools)
- [Evidence Collection](#evidence-collection)
- [Incident Management](#incident-management)
- [Linux Evidence Collection](#linux-evidence-collection)
- [Log Analysis Tools](#log-analysis-tools)
- [Memory Analysis Tools](#memory-analysis-tools)
- [Memory Imaging Tools](#memory-imaging-tools)
- [Sandboxing/Reversing Tools](#sandboxingreversing-tools)
- [Scanner Tools](#scanner-tools)
- [Windows Evidence Collection](#windows-evidence-collection)

## IR Tools Collection


### Disk Image Creation Tools

* [AccessData FTK Imager](http://accessdata.com/product-download/?/support/adownloads#FTKImager) - Forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems.
* [Bitscout](https://github.com/vitaly-kamluk/bitscout) - Bitscout by Vitaly Kamluk helps you build your fully-trusted customizable LiveCD/LiveUSB image to be used for remote digital forensics (or perhaps any other task of your choice). It is meant to be transparent and monitorable by the owner of the system, forensically sound, customizable and compact.
* [GetData Forensic Imager](http://www.forensicimager.com/) - Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats.
* [Guymager](http://guymager.sourceforge.net) - Free forensic imager for media acquisition on Linux.
* [Magnet ACQUIRE](https://www.magnetforensics.com/magnet-acquire/) - ACQUIRE by Magnet Forensics allows various types of disk acquisitions to be performed on Windows, Linux, and OS X as well as mobile operating systems.

### Evidence Collection

* [Acquire](https://github.com/fox-it/acquire) - Acquire is a tool to quickly gather forensic artifacts from disk images or a live system into a lightweight container. This makes Acquire an excellent tool to, among others, speedup the process of digital forensic triage. It uses [Dissect](https://github.com/fox-it/dissect) to gather that information from the raw disk, if possible.
* [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - The artifactcollector project provides a software that collects forensic artifacts on systems.
* [bulk_extractor](https://github.com/simsong/bulk_extractor) - Computer forensics tool that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. Because of ignoring the file system structure, the program distinguishes itself in terms of speed and thoroughness.
* [Cold Disk Quick Response](https://github.com/rough007/CDQR) - Streamlined list of parsers to quickly analyze a forensic image file (`dd`, E01, `.vmdk`, etc) and output nine reports.
* [CyLR](https://github.com/orlikoski/CyLR) - The CyLR tool collects forensic artifacts from hosts with NTFS file systems quickly, securely and minimizes impact to the host.
* [Forensic Artifacts](https://github.com/ForensicArtifacts/artifacts) - Digital Forensics Artifact Repository
* [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
* [Live Response Collection](https://www.brimorlabs.com/tools/) - Automated tool that collects volatile data from Windows, OSX, and \*nix based operating systems.
* [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun) - Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition.
* [SPECTR3](https://github.com/alpine-sec/SPECTR3) - Acquire, triage and investigate remote evidence via portable iSCSI readonly access
* [UAC](https://github.com/tclahr/uac) - UAC (Unix-like Artifacts Collector) is a Live Response collection script for Incident Response that makes use of native binaries and tools to automate the collection of AIX, Android, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD and Solaris systems artifacts.

### Incident Management

* [Catalyst](https://github.com/SecurityBrewery/catalyst) - A free SOAR system that helps to automate alert handling and incident response processes.
* [CyberCPR](https://www.cybercpr.com) - Community and commercial incident management tool with Need-to-Know built in to support GDPR compliance while handling sensitive incidents.
* [Cyphon](https://medevel.com/cyphon/) - Cyphon eliminates the headaches of incident management by streamlining a multitude of related tasks through a single platform. It receives, processes and triages events to provide an all-encompassing solution for your analytic workflow — aggregating data, bundling and prioritizing alerts, and empowering analysts to investigate and document incidents.
* [CORTEX XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) - Paloalto security orchestration, automation and response platform with full Incident lifecycle management and many integrations to enhance automations.
* [DFTimewolf](https://github.com/log2timeline/dftimewolf) - A framework for orchestrating forensic collection, processing and data export.
* [DFIRTrack](https://github.com/dfirtrack/dfirtrack) - Incident Response tracking application handling one or more incidents via cases and tasks with a lot of affected systems and artifacts.
* [Fast Incident Response (FIR)](https://github.com/certsocietegenerale/FIR/) - Cybersecurity incident management platform designed with agility and speed in mind. It allows for easy creation, tracking, and reporting of cybersecurity incidents and is useful for CSIRTs, CERTs and SOCs alike.
* [RTIR](https://www.bestpractical.com/rtir/) - Request Tracker for Incident Response (RTIR) is the premier open source incident handling system targeted for computer security teams. We worked with over a dozen CERT and CSIRT teams around the world to help you handle the ever-increasing volume of incident reports. RTIR builds on all the features of Request Tracker.
* [Sandia Cyber Omni Tracker (SCOT)](https://github.com/sandialabs/scot) - Incident Response collaboration and knowledge capture tool focused on flexibility and ease of use. Our goal is to add value to the incident response process without burdening the user.
* [Shuffle](https://github.com/frikky/Shuffle) - A general purpose security automation platform focused on accessibility.
* [threat_note](https://github.com/defpoint/threat_note) - Lightweight investigation notebook that allows security researchers the ability to register and retrieve indicators related to their research.
* [Zenduty](https://www.zenduty.com) - Zenduty is a novel incident management platform providing end-to-end incident alerting, on-call management and response orchestration, giving teams greater control and automation over the incident management lifecycle.



### Linux Evidence Collection

* [FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux) - FastIR for Linux collects different artifacts on live Linux and records the results in CSV files.
* [MAGNET DumpIt](https://github.com/MagnetForensics/dumpit-linux) - Fast memory acquisition open source tool for Linux written in Rust. Generate full memory crash dumps of Linux machines.

### Log Analysis Tools

* [AppCompatProcessor](https://github.com/mbevilacqua/appcompatprocessor) - AppCompatProcessor has been designed to extract additional value from enterprise-wide AppCompat / AmCache data beyond the classic stacking and grepping techniques.
* [APT Hunter](https://github.com/ahmedkhlief/APT-Hunter) - APT-Hunter is Threat Hunting tool for windows event logs.
* [Chainsaw](https://github.com/countercept/chainsaw) - Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs.
* [Event Log Explorer](https://eventlogxp.com/) - Tool developed to quickly analyze log files and other data.
* [Event Log Observer](https://lizard-labs.com/event_log_observer.aspx) - View, analyze and monitor events recorded in Microsoft Windows event logs with this GUI tool.
* [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Hayabusa is a Windows event log fast forensics timeline generator and threat hunting tool created by the Yamato Security group in Japan.
* [Kaspersky CyberTrace](https://support.kaspersky.com/13850) - Threat intelligence fusion and analysis tool that integrates threat data feeds with SIEM solutions. Users can immediately leverage threat intelligence for security monitoring and incident report (IR) activities in the workflow of their existing security operations.
* [Log Parser Lizard](https://lizard-labs.com/log_parser_lizard.aspx) - Execute SQL queries against structured log data: server logs, Windows Events, file system, Active Directory, log4net logs, comma/tab separated text, XML or JSON files. Also provides a GUI to Microsoft LogParser 2.2 with powerful UI elements: syntax editor, data grid, chart, pivot table, dashboard, query manager and more.
* [Lorg](https://github.com/jensvoid/lorg) - Tool for advanced HTTPD logfile security analysis and forensics.
* [Logdissect](https://github.com/dogoncouch/logdissect) - CLI utility and Python API for analyzing log files and other data.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Tool to investigate malicious Windows logon by visualizing and analyzing Windows event log.
* [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems already containing an extensive ruleset.
* [StreamAlert](https://github.com/airbnb/streamalert) - Serverless, real-time log data analysis framework, capable of ingesting custom data sources and triggering alerts using user-defined logic.
* [SysmonSearch](https://github.com/JPCERTCC/SysmonSearch) - SysmonSearch makes Windows event log analysis more effective and less time consuming by aggregation of event logs.
* [WELA](https://github.com/Yamato-Security/WELA) - Windows Event Log Analyzer aims to be the Swiss Army knife for Windows event logs.
* [Zircolite](https://github.com/wagga40/Zircolite) - A standalone and fast SIGMA-based detection tool for EVTX or JSON.

### Memory Analysis Tools

* [AVML](https://github.com/microsoft/avml) - A portable volatile memory acquisition tool for Linux.
* [Evolve](https://github.com/JamesHabben/evolve) - Web interface for the Volatility Memory Forensics Framework.
* [inVtero.net](https://github.com/ShaneK2/inVtero.net) - Advanced memory analysis for Windows x64 with nested hypervisor support.
* [LiME](https://github.com/504ensicsLabs/LiME) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD.
* [MalConfScan](https://github.com/JPCERTCC/MalConfScan) - MalConfScan is a Volatility plugin extracts configuration data of known malware. Volatility is an open-source memory forensics framework for incident response and malware analysis. This tool searches for malware in memory images and dumps configuration data. In addition, this tool has a function to list strings to which malicious code refers.
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis.
* [Memoryze for Mac](https://www.fireeye.com/services/freeware/memoryze.html) - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however.
* [MemProcFS] (https://github.com/ufrisk/MemProcFS) - MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system.
* [Orochi](https://github.com/LDO-CERT/orochi) - Orochi is an open source framework for collaborative forensic memory dump analysis.
* [Rekall](http://www.rekall-forensic.com/) - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples.
* [Volatility](https://github.com/volatilityfoundation/volatility) - Advanced memory forensics framework.
* [Volatility 3](https://github.com/volatilityfoundation/volatility3) - The volatile memory extraction framework (successor of Volatility)
* [VolatilityBot](https://github.com/mkorman90/VolatilityBot) - Automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase, or to help the investigator in the first steps of performing a memory analysis investigation.
* [VolDiff](https://github.com/aim4r/VolDiff) - Malware Memory Footprint Analysis based on Volatility.
* [WindowsSCOPE](http://www.windowsscope.com/windowsscope-cyber-forensics/) - Memory forensics and reverse engineering tool used for analyzing volatile memory offering the capability of analyzing the Windows kernel, drivers, DLLs, and virtual and physical memory.

### Memory Imaging Tools

* [Belkasoft Live RAM Capturer](http://belkasoft.com/ram-capturer) - Tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system.
* [Linux Memory Grabber](https://github.com/halpomeranz/lmg/) - Script for dumping Linux memory and creating Volatility profiles.
* [MAGNET DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows) - Fast memory acquisition tool for Windows (x86, x64, ARM64). Generate full memory crash dumps of Windows machines.
* [Magnet RAM Capture](https://www.magnetforensics.com/free-tool-magnet-ram-capture/) - Free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows.
* [OSForensics](http://www.osforensics.com/) - Tool to acquire live memory on 32-bit and 64-bit systems. A dump of an individual process’s memory space or physical memory dump can be done.


### Sandboxing/Reversing Tools

* [Any Run](https://app.any.run/) - Interactive online malware analysis service for dynamic and static research of most types of threats using any environment.
* [CAPA](https://github.com/mandiant/capa) - detects capabilities in executable files. You run it against a PE, ELF, .NET module, or shellcode file and it tells you what it thinks the program can do.
* [CAPEv2](https://github.com/kevoreilly/CAPEv2) - Malware Configuration And Payload Extraction.
* [Cutter](https://github.com/rizinorg/cutter) - Free and Open Source Reverse Engineering Platform powered by rizin.
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - Software Reverse Engineering Framework.
* [Hybrid-Analysis](https://www.hybrid-analysis.com/) - Free powerful online sandbox by CrowdStrike.
* [Intezer](https://analyze.intezer.com/#/) - Intezer Analyze dives into Windows binaries to detect micro-code similarities to known threats, in order to provide accurate yet easy-to-understand results.
* [Joe Sandbox (Community)](https://www.joesandbox.com/) - Joe Sandbox detects and analyzes potential malicious files and URLs on Windows, Android, Mac OS, Linux, and iOS for suspicious activities; providing comprehensive and detailed analysis reports.
* [Mastiff](https://github.com/KoreLogicSecurity/mastiff) - Static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
* [Metadefender Cloud](https://www.metadefender.com) - Free threat intelligence platform providing multiscanning, data sanitization and vulnerability assessment of files.
* [Radare2](https://github.com/radareorg/radare2) - Reverse engineering framework and command-line toolset.
* [Reverse.IT](https://www.reverse.it/) - Alternative domain for the Hybrid-Analysis tool provided by CrowdStrike.
* [Rizin](https://github.com/rizinorg/rizin) - UNIX-like reverse engineering framework and command-line toolset
* [StringSifter](https://github.com/fireeye/stringsifter) - A machine learning tool that ranks strings based on their relevance for malware analysis.
* [Threat.Zone](https://app.threat.zone) - Cloud based threat analysis platform which include sandbox, CDR and interactive analysis for researchers.
* [Valkyrie Comodo](https://valkyrie.comodo.com) - Valkyrie uses run-time behavior and hundreds of features from a file to perform analysis.
* [Viper](https://github.com/viper-framework/viper) - Python based binary analysis and management framework, that works well with Cuckoo and YARA.
* [Virustotal](https://www.virustotal.com) - Free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners.
* [Visualize_Logs](https://github.com/keithjjones/visualize_logs) - Open source visualization library and command line tools for logs (Cuckoo, Procmon, more to come).
* [Yomi](https://yomi.yoroi.company) - Free MultiSandbox managed and hosted by Yoroi.

### Scanner Tools

* [Fenrir](https://github.com/Neo23x0/Fenrir) - Simple IOC scanner. It allows scanning any Linux/Unix/OSX system for IOCs in plain bash. Created by the creators of THOR and LOKI.
* [LOKI](https://github.com/Neo23x0/Loki) - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
* [Spyre](https://github.com/spyre-project/spyre) - Simple YARA-based IOC scanner written in Go


### Windows Evidence Collection

* [AChoir](https://github.com/OMENScan/AChoir) - Framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
* [Crowd Response](http://www.crowdstrike.com/community-tools/) - Lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
* [Cyber Triage](http://www.cybertriage.com) - Cyber Triage has a lightweight collection tool that is free to use. It collects source files (such as registry hives and event logs), but also parses them on the live host so that it can also collect the executables that the startup items, scheduled, tasks, etc. refer to. It's output is a JSON file that can be imported into the free version of Cyber Triage. Cyber Triage is made by Sleuth Kit Labs, which also makes Autopsy. 
* [DFIR ORC](https://dfir-orc.github.io/) - DFIR ORC is a collection of specialized tools dedicated to reliably parse and collect critical artifacts such as the MFT, registry hives or event logs. DFIR ORC collects data, but does not analyze it: it is not meant to triage machines. It provides a forensically relevant snapshot of machines running Microsoft Windows. The code can be found on [GitHub](https://github.com/DFIR-ORC/dfir-orc).
* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Tool that collects different artifacts on live Windows systems and records the results in csv files. With the analyses of these artifacts, an early compromise can be detected.
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
* [Hoarder](https://github.com/muteb/Hoarder) - Collecting the most valuable artifacts for forensics or incident response investigations.
* [IREC](https://binalyze.com/products/irec-free/) - All-in-one IR Evidence Collector which captures RAM Image, $MFT, EventLogs, WMI Scripts, Registry Hives, System Restore Points and much more. It is FREE, lightning fast and easy to use.
* [Invoke-LiveResponse](https://github.com/mgreen27/Invoke-LiveResponse) -  Invoke-LiveResponse is a live response tool for targeted collection.
* [IOC Finder](https://www.fireeye.com/services/freeware/ioc-finder.html) - Free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Support for Windows only. No longer maintained. Only fully supported up to Windows 7 / Windows Server 2008 R2.
* [IRTriage](https://github.com/AJMartel/IRTriage) - Tool for automated evidence collection and analysis in Windows environments during incident response.
* [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) - Kroll Artifact Parser and Extractor (KAPE) by Eric Zimmerman. A triage tool that finds the most prevalent digital artifacts and then parses them quickly. Great and thorough when time is of the essence.
* [LOKI](https://github.com/Neo23x0/Loki) - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
* [MEERKAT](https://github.com/TonyPhipps/Meerkat) - PowerShell-based triage and threat hunting for Windows.
* [Panorama](https://github.com/AlmCo/Panorama) - Fast incident overview on live Windows systems.
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - Live disk forensics platform, using PowerShell.
* [PSRecon](https://github.com/gfoss/PSRecon/) - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
* [RegRipper](https://github.com/keydet89/RegRipper3.0) - Open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.
