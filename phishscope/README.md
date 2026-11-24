# PhishScope

**A beginner-friendly tool that checks whether an email looks like a phishing attempt, then explains why.**

!\[PhishScope report for a phishing email](docs/report-phishing.png)

You give PhishScope a suspicious email (saved as an `.eml` file). It returns:

* a **risk score** from 0 to 100,
* a **verdict**: Low risk, Suspicious, or Likely phishing,
* the **reasons** behind the score, in a clean report you can open in your browser.

This is the kind of first check a SOC (Security Operations Center) analyst does many times a day. PhishScope automates it.

Important: PhishScope is a triage helper, not a guarantee. A high score means "be careful". A low score does not prove an email is safe. A human should always make the final decision.



## Table of contents

* [What is phishing?](#what-is-phishing)
* [What it checks](#what-it-checks)
* [Quick start](#quick-start)
* [Screenshots](#screenshots)
* [How the score works](#how-the-score-works)
* [Safety by design](#safety-by-design)
* [MITRE ATT\&CK mapping](#mitre-attck-mapping)
* [Project layout](#project-layout)
* [Troubleshooting](#troubleshooting)
* [Limitations and roadmap](#limitations)
* [License](#license)



## What is phishing?

Phishing is a fake email that pretends to come from a trusted company or person. Its goal is to trick you into clicking a harmful link, opening a harmful file, or typing your password into a fake website.

Checking an email by hand means inspecting many small details. PhishScope checks them all in a second and shows its reasoning, so a person can decide faster and with more confidence.

\---

## What it checks

|Check|What it means|Why it matters|
|-|-|-|
|**SPF, DKIM, DMARC**|Three "ID checks" that mail servers run to confirm a sender is who they claim to be|A failed check suggests the sender is faking their identity|
|**From vs Reply-To / Return-Path**|Where the email says it comes from, compared with where replies and bounces go|Scammers often hide their real address here|
|**Brand impersonation**|Display name says "PayPal", but the real address belongs to another domain|The name is easy to fake, the domain is not|
|**Disguised links**|The text you see (`paypal.com`) differs from where the link really goes|One of the strongest signs of phishing|
|**Risky links**|Raw IP addresses, URL shorteners (like bit.ly), look-alike domains, `@` tricks, plain HTTP|They hide or weaken the real destination|
|**Attachments**|A fingerprint (hash) of each file, its real type, risky types like `.exe`, and double extensions like `scan.pdf.exe`|Malware is often disguised as a harmless document|
|**Pressure language**|Words like "urgent" and "within 24 hours"|Scammers want you to panic and click|
|**Origin IP**|Public IP addresses the email travelled through|A starting point for deeper investigation|

### Words explained

* **Header:** the hidden technical information at the top of an email, like the postal stamps on a letter.
* **Hash:** a unique fingerprint of a file. You can search it on VirusTotal to see whether it is known malware.
* **File signature (magic bytes):** the first few bytes of a file that reveal its real type. A real PDF starts with `%PDF`, and a Windows program starts with `MZ`, whatever the file is named.
* **Defanged link:** a link made unclickable on purpose, like `hxxp://evil\[.]example`, so nobody opens it by accident.
* **Double extension:** a file named `invoice.pdf.exe`. Windows may hide the last part, so it looks like a PDF.

!\[Links and attachments section of the report](docs/report-details.png)



## Quick start

**You need:** Python 3 (tested on Python 3.12). There is nothing else to install.

**1. Download the project** and open a terminal (Command Prompt on Windows) **in the project folder**, the one that contains `phishscope`, `samples` and `tests`.



**2. Try it on the included fake emails:**

python -m phishscope.cli samples/phishing\_sample.eml
python -m phishscope.cli samples/legit\_sample.eml


**3. Save an HTML report:**

python -m phishscope.cli samples/phishing\_sample.eml -o report.html


**4. Or use the upload page:**

python -m phishscope.web


Then open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser and upload an `.eml` file. Press `Ctrl + C` in the terminal to stop the server.



### How to get an `.eml` file

An `.eml` file is an email saved as a file, including its hidden technical details.

* **Gmail:** open the email, click the three dots, choose **Download message**.
* **Outlook:** drag the email to your desktop, or use File, then Save As.

Privacy:  never commit real emails to GitHub. They contain personal information. Only the fake files in `samples/` belong in this repository.



## Screenshots

**Command line**

!\[Command line output](docs/cli-output.png)

**Upload page**

!\[Local upload page](docs/web-upload.png)

**A normal email scores low**

!\[Low risk report](docs/report-safe.png)

**Automated tests passing**

!\[Tests passing](docs/tests-pass.png)



## How the score works

Each red flag adds points, for example failed SPF +20, disguised link +25, file type mismatch +25. The total is capped at 100.

|Score|Verdict|
|-|-|
|0 to 19|Low risk|
|20 to 49|Suspicious|
|50 and above|Likely phishing|

If a file is empty or is not a real email, PhishScope says **"Could not read this file as an email"** instead of guessing.



## Safety by design

* The email is **never opened or run**. Attachments are only fingerprinted and checked.
* Every link in the report is **defanged**.
* Email content is **escaped** in the report, so code hidden in an email cannot run in the report page.
* The upload page only works on your own computer (`127.0.0.1`), and uploaded emails are analysed in memory and never saved.
* The sample emails are fake and harmless.



## MITRE ATT\&CK mapping

|Technique|Where PhishScope helps|
|-|-|
|T1566.001 Spearphishing Attachment|Attachment type, extension and hash checks|
|T1566.002 Spearphishing Link|Link mismatch, shortener and IP checks|
|T1036.007 Masquerading: Double File Extension|Double extension and file signature checks|
|T1656 Impersonation|Display name and domain checks|



## Project layout


phishscope/
├── phishscope/
│   ├── analyzer.py   # reads the email, runs the checks, calculates the score
│   ├── report.py     # builds the HTML report
│   ├── cli.py        # command line tool
│   └── web.py        # local upload page
├── samples/          # fake phishing and normal emails for practice
├── tests/            # automatic tests
├── docs/             # screenshots used in this README
└── README.md




## Troubleshooting

|Problem|Fix|
|-|-|
|`No module named phishscope.cli`|You are in the wrong folder. Use `dir` (Windows) or `ls` and `cd` until you can see `phishscope`, `samples` and `tests` together|
|Browser says "This site can't be reached"|The upload server is not running. Start it with `python -m phishscope.web` and keep that window open|
|Port already in use|An old server is still running. Close the old terminal window or press `Ctrl + C` in it|
|"Could not read this file as an email"|The file is empty or not a real `.eml`. Download the email again as `.eml`|
|Two commands run together as one line|Run each command separately and press Enter after each|



## Limitations

* Domain comparison is simplified (no full public-suffix list).
* SPF, DKIM and DMARC results are read from the email headers, not re-checked with DNS.
* No online reputation lookups yet, which keeps the tool offline and free of dependencies.
* It checks one email at a time.

## Roadmap

* \[ ] Optional VirusTotal and AbuseIPDB lookups for hashes, IPs and domains
* \[ ] Check a whole folder of emails at once
* \[ ] Support for `.msg` files
* \[ ] Export results as CSV



## Author

Built by **\[Your Name]** as part of my cybersecurity and digital forensics practice.
Connect with me on [LinkedIn](https://www.linkedin.com/in/your-profile).

## License

MIT. See the [LICENSE](LICENSE) file.

