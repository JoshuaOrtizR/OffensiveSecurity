**Discovering Sensitive Files**

**Information Gathering (Files & Directories)**

This phase involves identifying and locating files and directories within the target website. A valuable tool for this task is **dirb**.

* **Understanding dirb:**
    * To learn more about dirb's usage and options, execute:
        ```bash
        man dirb 
        ```
        This command provides detailed information about the tool and its functionalities.

* **Targeting a Website:**
    * **Focus on Websites:** When using dirb, target a website's URL, not an IP address.
    * **Usage:** A basic command to use dirb against a website would be:
        ```bash
        dirb http://10.20.14.204/mutillidae 
        ```
        This command attempts to discover hidden files and directories within the specified website.

**Hands-on:**

![1](https://github.com/user-attachments/assets/aba9be12-b3d2-44aa-8343-d4476fc04801)

![2](https://github.com/user-attachments/assets/c018b9c6-6b1b-4c65-a766-ec2d9a22dd74)
