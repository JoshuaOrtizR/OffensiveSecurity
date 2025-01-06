**GET Method**

* **Purpose:** Primarily used to **retrieve data** from a server. 
* **Data Transmission:** 
    * Data is appended to the **URL** as **query parameters** (e.g., `?name=John&age=30`).
    * This makes the data visible in the URL itself.
* **Idempotency:** 
    * Idempotent, meaning multiple identical requests have the same effect as a single request. 
* **Caching:** 
    * GET requests are **cacheable** by default. 
* **Security:** 
    * **Less secure** than POST due to data exposure in the URL.
    * **Not suitable** for sensitive information.
* **Examples:**
    * Fetching a webpage (e.g., `https://www.udemy.com`)
    * Searching for products on an e-commerce site
    * Retrieving data from an API

**POST Method**

* **Purpose:** 
    * Used to **send data** to a server to **create or update** resources.
    * Can also trigger server-side actions like processing forms or uploading files.
* **Data Transmission:** 
    * Data is sent in the **request body** of the HTTP message.
    * Not visible in the URL.
* **Idempotency:** 
    * **Not idempotent.** 
    * Multiple identical POST requests may have different effects on the server.
* **Caching:** 
    * Generally **not cacheable** by default.
* **Security:** 
    * **More secure** than GET as data is not exposed in the URL.
* **Examples:**
    * Submitting a form (e.g., login, registration)
    * Uploading files
    * Creating new resources (e.g., adding a new user)

**Differences:**

| Feature | GET Method | POST Method |
|---|---|---|
| Purpose | Retrieve data | Send data, create/update resources |
| Data Location | URL | Request body |
| Visibility | Data visible in URL | Data not visible in URL |
| Idempotency | Idempotent | Not idempotent |
| Caching | Cacheable | Generally not cacheable |
| Security | Less secure | More secure |

**Choosing the Right Method:**

* **Use GET for:**
    * Retrieving data (e.g., fetching a webpage, searching)
    * Simple, non-sensitive operations
* **Use POST for:**
    * Submitting forms (login, registration)
    * Uploading files
    * Creating or updating resources
    * Sending sensitive data

 ##
 **Request Codes**

* **GET:** Retrieves data from the server. 
    * Example: Fetching a webpage (e.g., `https://www.example.com`)
* **HEAD:** Similar to GET, but only retrieves the response headers, not the actual content. 
    * Useful for checking if a resource exists or getting information like file size.
* **POST:** Sends data to the server to create or update resources. 
    * Example: Submitting a form, uploading files.
* **TRACE:** 
    * Sends a message to the server and asks it to return the message received. 
    * Used for testing and diagnostics.
* **OPTIONS:** 
    * Asks the server which HTTP methods are supported for a specific resource.
* **CONNECT:** 
    * Establishes a tunnel to a server on a different port. 
    * Primarily used to enable SSL/TLS communication through an HTTP proxy.
* **PUT:** 
    * Replaces the entire representation of a resource with the request payload.
    * Idempotent (multiple requests have the same effect as a single request).
* **DELETE:** 
    * Requests that the server delete the specified resource.

**Return Codes (Status Codes)**

* **200 OK:** The request was successful.
* **301 Moved Permanently:** The requested resource has been permanently moved to a new location.
* **400 Bad Request:** The server could not understand the request due to invalid syntax.
* **401 Unauthorized:** The request requires user authentication.
* **403 Forbidden:** The server understood the request but refuses to fulfill it.
* **404 Not Found:** The requested resource could not be found on the server.
* **500 Internal Server Error:** The server encountered an unexpected condition that prevented it from fulfilling the request.



