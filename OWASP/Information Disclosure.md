
**Information Disclosure**

Information disclosure happens when a website accidentally reveals sensitive data. This could be user details to internal company information. 

* **Security Risks:** Leaking user data (like financial info) is a major problem. 
* **Attack Surface:** Disclosing technical details can help attackers find other vulnerabilities.

**Common Causes:**

* **Accidental Leaks:** Developers sometimes leave hidden comments or debug features enabled.
* **Poor Configuration:** Misconfigured settings can expose sensitive information.
* **Flawed Design:** How the website handles errors can reveal unexpected details.

**Impact:**

* **Direct:** Leaking sensitive user data can have immediate and severe consequences.
* **Indirect:** Disclosing technical info can give attackers the information they need to launch further attacks.

**Finding and Exploiting:**

* **Look for:** Hidden directories, source code snippets, error messages that reveal too much, and inconsistencies in how the website responds.
* **Labs:** Practice your skills with our interactive labs.

**Prevention:**

* **Awareness:** Educate team about what information is sensitive.
* **Code Reviews:** Regularly review code for potential leaks.
* **Secure Defaults:** Use secure configurations for all your software.
* **Generic Error Messages:** Avoid providing detailed error messages to users.

##
**Hands-on**

Many websites use a file named 'robots.txt' to instruct search engines not to index certain pages or files. In this example, we attempted to access and download the 'robots.txt' file. 
Surprisingly, instead of the expected instructions, we found source code written in Java. This indicates a misconfiguration, as the 'robots.txt' file should contain plain text instructions, not source code. 
Further analysis of the source code revealed a connection builder designed to interact with a PostgreSQL database.

![1](https://github.com/user-attachments/assets/6d6178c7-398c-4448-ac60-57b54ffc89a8)

![2](https://github.com/user-attachments/assets/b5247e2b-b604-45b0-9a89-0c7942543677)

This connection builder likely includes sensitive information such as the database address and, importantly, the password. 
This discovery presents a significant security vulnerability. By obtaining the database credentials, an attacker could potentially gain unauthorized access to sensitive data within the database.

![4](https://github.com/user-attachments/assets/6c6bbeee-d2f3-4ad8-9676-1589f98f6902)
