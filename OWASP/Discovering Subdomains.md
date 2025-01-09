**Discovering Subdomains**

**Knockpy** is a open-source Python tool designed for comprehensive subdomain enumeration and reconnaissance. It leverages multiple sources to uncover hidden subdomains, aiding in various security assessments.

* **Subdomain Discovery:**
    -  Knockpy queries a wide array of public sources like Censys, VirusTotal, and passiveDNS to identify subdomains.
    -  It provides a list of all discovered subdomains, along with their associated IP addresses and other relevant information.
* **Recon & Vulnerability Assessment:**
    - **Target Identification:** By discovering subdomains, you can expand your attack surface and identify potential targets for further investigation.
    - **Infrastructure Mapping:** Knockpy helps map the target's infrastructure, revealing hidden servers, services, and technologies.
    - **Vulnerability Hunting:** Once you have a list of subdomains, you can perform targeted vulnerability scans to identify and exploit weaknesses.

**Usage:**

1. **Installation:** Install Knockpy using pip: `pip install knockpy`
2. **Target Input:** Specify the target domain you want to enumerate.
3. **Subdomain Discovery:** Run Knockpy with the target domain as input. It will automatically query the configured sources and generate a list of subdomains.
4. **Further Analysis:** Analyze the discovered subdomains. Investigate their infrastructure, identify potential vulnerabilities, and prioritize targets for further assessment.

**Hands-On:**

```bash
knockpy -domain google.com  --recon 
```
![1](https://github.com/user-attachments/assets/8090a786-2d24-450f-bb3f-b878627c4355)

![2](https://github.com/user-attachments/assets/ffc86fb9-924e-43a0-be95-d2bc43a2259d)

![3](https://github.com/user-attachments/assets/508cd5e5-c0f4-4128-aee7-d457d9fed448)
