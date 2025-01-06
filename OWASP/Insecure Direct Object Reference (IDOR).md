**Broken Access Control: Insecure Direct Object Reference (IDOR)**

 * IDOR is a type of broken access control vulnerability. 
 * It occurs when an application directly exposes internal implementation objects (like database keys, file paths, or unique identifiers) in URLs or other requests. 
 * If an attacker can guess or manipulate these identifiers, they can bypass authorization checks and access data or functionality they shouldn't have access to.

* **Impact:**

    * **Data breaches:** Access to sensitive information like financial data, personal records, or confidential documents.
    * **Account hijacking:** Attackers can gain control of other users' accounts.
    * **Data modification:** Unauthorized changes to data, such as altering financial transactions or modifying user settings.
    * **System disruption:** Attackers might be able to delete data, modify system configurations, or even gain control of the server.

* **Prevention and Mitigation:**

    * **Proper Authorization Checks:**
        * **Principle of Least Privilege:** Grant users only the necessary permissions.
        * **Session Management:** Implement strong session management techniques to prevent session hijacking.
        * **Input Validation:** Validate and sanitize all user input to prevent manipulation of identifiers.

**Hands-on**

We'll be intercepting information sent via POST requests within this chat environment.
Specifically, we're capturing the messages transmitted. By manipulating the POST request, we can dynamically alter the downloaded transcript.
For instance, if the transcript URL is 'transcrip/4', we can modify the ID to download transcripts for other conversations, even those that do not belong to us.
This vulnerability highlights an Insecure Direct Object Reference, where we can directly access resources based on their identifiers without proper authorization checks.

![Capture](https://github.com/user-attachments/assets/89b2b2e3-f298-4c77-a84b-15120499125a)

![2](https://github.com/user-attachments/assets/9d94a97b-01af-4520-a4db-93bfc4185ab8)
