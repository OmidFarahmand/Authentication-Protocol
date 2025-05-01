**Authentication-Protocol Report**  
**Author:** Omid Farahmand  
---

# Secure Photo Synchronization Implementation Report
## Executive summary section
This report outlines the implementation and design of the authentication and integrity mechanisms for securing Alice’s photo synchronization system. The implemented protocol will make sure that Alice’s device will be synchronized securely, even if the server is malicious.
The hash functions and message authentication codes are intended to detect modifications to the photo log by the attacker; furthermore, the report covers **man-in-the-middle (MITM) attacks**, **log tampering**, and **unauthorized access**. We use **timestamps**, **passwords**, and **HMACs** to keep the system secure. This will make sure to protect **authentication** and data **integrity** and **prevent session hijacking**.

--- 

## Part 1: Implementation report
### Authentication Protocol Implementation:

Our authentication protocol implementation relies on **Message authentication codes (MACs)** to ensure the **integrity of log** entries. We can detect any unauthorized changes that can happen through the system with the help of hash functions. Log Entries are securely connected to the previous record using HMACs, ensuring any modification to the log will break the chain throughout the system. The major key components that have been used in our protocol implementation include:

---

 **LogEntry Encoding & Decoding:** Each action, like registering a user or uploading a photo to the user, will be recorded as a **LogEntry**. Before sending log entries into the server, they must be converted into a **byte format**. This is where the **codec.encode()** will safely store this operation. 
```python
log_entry = LogEntry(version=1, opcode=2, photo_id=10, ...) 
encoded_entry = codec.encode(log_entry)  # Converts LogEntry into bytes 
```
 This ensures that **log** entries follow the correct format and structure. The corrupted or tampered log entries will be avoided with the help of clients. This operation will ensure the integrity and security of the system. 

 ---

**Checking HMAC Integrity:** Having a secure authenticity and integrity in our system is crucial. Only Alice’s trusted device should verify the integrity of the stored data, and this is implemented when each option is assigned an **HMAC (this_hmac)**, which is generated from Alice’s **user_secret** symmetric key. **The prev_hmac** has a log entry, which makes a cryptographic chain that prevents any **alteration**. In any case, if the attacker tries to **modify** (insert, delete) a log entry, the HMAC will no longer be available, and the chain will break. In the **synchronization process**, the client will look at the contents and the **prev_hmac**, which will compare it against the stored prev_hmac to detect any **tampering**. Also, an exception **(SynchronizationError)** will be raised if any difference is found between the computed HMAC.

--- 

**Photo Hashing:** Instead of saving photos in the log, our system will store each uploaded image in a **unique hash** (photo_hash) for each uploaded image. After the photo is received by the client, the client will **recalculate** its new hash **(crypto.data_hash(photo_blob))** and compare it with the original values stored **(photo_hash)** in the log. If the hashes match, this means that the photo has not been altered, and if it doesn't match, it means it’s been altered. This ensures that the photo remains unchanged, which avoids any **unauthorized replacement** or alteration. 

---

**Secure Synchronization:** In the Synchronization phase, in order to keep the data up to date, first, the client requests a **SynchronizeRequest** to the server asking for the new log entries. After that, the server will provide a **sequence of log entries**, which the client will verify with the following steps:

**Request New Entries:** The SynchronizeRequest will be sent to the server, requesting log entries with version numbers higher than its recorded version **(_last_log_number)**.

**Version checks:** To make sure each new entry follows exactly one correct sequence **greater** than the **previous entry**. 

**HMAC Chain Verification:** To confirm **prev_hmac** will match the previous value of the HMAC, maintaining the **integrity**.

**Entry Specific Validation:** If it’s a **PUT_PHOTO** operation, the photo is **retrieved**, and the computed hash is **computed and verified**, which will be stored in **photo_hash**. This will not work if any of these checks fail, so the synchronization process will be stopped, and exceptions will be raised to prevent any security risks. 

---

**Handling Authentication and Session Tokens:**
The client will **authenticate** using an **auth_secret** for accessing the server in the **registration (register())** and the **login (login())** process. After the authentication process, the server will issue a session token, in which all future requests of the client must be included. This will make sure that only authorized users can **interact** with the server, keeping **unauthorized** users out. 
If a session token is invalid, the server will **reject** the request, raising an **InvalidTokenError**. By combining these security measures, we ensure that our authentication protocols allow only Alice’s devices to **synchronize photos**, even when communicating with an **untrusted server**. Any inconsistency or tampering attempts are **detected and rejected**. 

---

### Defense Against Attacks

The implementation defends against the listed malicious behaviors. Below is the outline of the potential attacks and the measures in place to defend against them.

---

**Photo Substitution Attack:** As was mentioned in the assignment instruction, one attack that could take place is when the **malicious server swaps** the requested photo with its own (replacing tim.jpg with john.jpg). In our process, each photo that is uploaded is **hashed** using **crypto.data_hash(photo_blob)**, making a unique **photo_hash**. The **_fetch_photo()** will be invoked when a device requests a photo, then it verifies that **crypto.data_hash(resp.photo_blob) == expected_hash**. Unmatched hashes will raise a Synchronization Error. It prevents altered photos from getting accepted. 

---

**Log Forgery Attack:** Another attack could happen when the server **fabricates** the **log entries** and adds **fake photos** to Alice’s album. Every log entry is authenticated with **HMAC (this_hmac)**, computed using **_compute_log_hmac()**. The **_synchronize()** method verifies the HMAC of every log entry, and any forged log entries will be detected and rejected since only Alice’s devices know the **symmetric key**. 

--- 

**Log Deletion Attack:** The server can also delete specific **log entries** to remove any evidence of **certain photos**. For example, Alice uploads a private photo to her album, so the system records a log entry for this procedure. Afterward, the **malicious server** deletes the log entry related to Alice’s uploads. So, when Alice wanted to connect to another device, her photo did not appear in the album, and there is no record of it being **uploaded**. To defend against this attack, a specific version of the number has been provided to each log entry. The **_synchronize()** method will make sure that each new log entry has exactly equal to **self._last_log_number + 1**, and if the entry is missing, the **synchronization** will raise an error preventing logs from being detected. 
```python
# The expected log version should be last_log_number + 1
if new_entry.version != self._last_log_number + 1:
    raise errors.SynchronizationError(
        f"Expected version {self._last_log_number+1}, got {new_entry.version}"
    )
```
---

**Log Duplication Attack:** The server can also **duplicate** the photo log entry, causing a single photo to appear more than once. Here, the **_synchronize()** method will also make sure that the **sequential log number** verifies HMACs to prevent **duplicate entries**. This will make sure that there is no duplicate made. If it decides to **duplicate the entry**, it will reject it. The recompute expected HMAC for new entry is:
```python
# Recompute expected HMAC for new entry
expected_hmac = self._compute_log_hmac(
                    version=new_entry.version,
                    opcode=new_entry.opcode,
                    photo_id=new_entry.photo_id,
                    photo_hash=new_entry.photo_hash,
                    prev_hmac=new_entry.prev_hmac,
                )
                if expected_hmac != new_entry.this_hmac:
                    raise errors.SynchronizationError("this_hmac verification failed")
```

---

**Log Tampering Attack:** In Log Tampering attacks, the server can modify the **log entry** and send different versions to different devices. Every log entry’s **HMAC** is computed using **contents** and the **previous entry’s HMAC (prev_hmac)**. The expected HMAC will be recalculated by the **_synchronize()** methods and will be compared with the received **this_hmac**. If they don’t match, the log entry will be rejected, preventing any unauthorized modification.

--- 

**Partial Log Response Attack:** The server can hide certain photos and return only some parts of the log. For instance, Alice uploads five photos to her album from her phone, so the system will record a log entry for every single photo. After that, Alice synced her data on her laptop, but the server only returned three of the photos while excluding the other two. So, Alice's laptop has no way of knowing that the photos exist. Therefore, in this scenario, the client will apply strict **sequential versioning**. The **_synchronize()** will detect the log entry to match **last_log_number + 1**, and if it doesn't, the expected synchronization will be stopped. This ensures that all log entries are considered, preventing the server from omitting any data.

---

**Additional Malicious Server Behaviors:** Some other unexpected **malicious behaviors** can happen to the server. One of them is when the server reorders the log and changes the sequence of the events. The defence mechanism that has been used for this procedure is that only the client can enforce version order **(version = self._last_log_number + 1)**, and as always, if the **out-of-sequence log** is detected, the **synchronization** will be halted. Alice can be **re-registered** by the **malicious server**, causing an **authentication** issue and invalidating her session. So, in this case, the **register()** method will allow only one register attempt and blocks any further attempts for Alice to re-authenticate. This will make sure that only Alice’s session is secure once she registers against the **unauthorized entity**. 

---

By combining all these techniques mentioned above, we can make sure we create a synchronization system that is secure, and guarantees only Alice's device will receive the correct photos.

## Part 2: System security questions

1- The solution suggests that instead of the client generating the timestamps to the server, the server generates its timestamps and provides them to the user, which the clients will compute as **HMAC (password, server_timestamp)**. After this, the client will send its HMAC to the server, which can introduce some security **vulnerabilities** such as **man-in-the-middle attacks (MITM)** and **replay attacks**. 


---
**Replay Attack:** occurs when the server sends a **timestamp t** to the client, which the client will compute the **HMAC (password,t)** and send back to the server. During the process, the attacker **eavesdrops on the network traffic** and records the client’s HMAC response, which can replays the same HMAC to the server and log in as the users. This makes it an **MITM** attack. This shows the vulnerability in the system since the attacker can reuse the old login messages to get unauthorized access to the system because there are no predictable **timestamps t**, and it does not change frequently. Even if the timestamps have a short-range period (e.g., within 1 minute), the attacker can still succeed; it has a small window to **replay the attack**. The situation can also worsen when the server **crashes or resets** since the server forgets the current time; the server timestamps will be sent on **January 1, 1980**, to the client during authentication, even if the legitimate client is on the present date. In this case, if the attacker has recorded the valid login request that used **HMAC (password, 1980)**, it can continuously **replay the attack** since the server time is incorrect. 

---


**MITM Attack** happen with timesmap being manipulated. This is a **timestamp manipulation**, where the server sends **timestamp t plaintext** over the network, and the MITM attacker will **intercept and modify** the message before forwarding it to the client. The client unknowingly processes HMAC with the **fake timestamp (password, fake_t)**. After that, the attacker will replays the correct timestamp t to the server with a **different HMAC**. The system will be tricked, and this will lead to login failures of the **legitimate user**. This is unsafe as well because if the server blindly acknowledges the timestamp of the client without **authenticating**, the attacker can manipulate the login process, which leads to **session hijacking** (gaining unauthorized access to the user’s session) or even making the client use its old timestamps.


---

**Server Clock Manipulation** (Denial of Service) which is another man-in-the-middle attack (MITM) that can be launch a **denial of service (DoS)** attack by **overwhelming** the server with **incorrect timestamps**. This can cause the server to **crash** and **desynchronize**, which makes the present timestamp outdated or reset to **January 1, 1980**. The attack will make the **legitimate client** fail the authentication process because they are using the correct real-world timestamp, while the server timestamp is outdated and incorrect. This can cause a major security threat to the client and the **communication server** since the attacker can block all legitimate users from accessing the system. If the server resets to January 1, 1980, the authentication will fail for all clients. Furthermore, this vulnerability can be exploited to deny access to all genuine users, causing authentication failure until the server gets fixed.

---

2- To protect the communication networks, against man-in-the-middle (MITM) attacks, we can propose a solution to integrate and enhance the authentication, integrity and session security. (1) Firstly, instead of sending a password in plaintext to the client, the client can implement an **HMAC-based authentication** token with the use of a **strong key** and a timestamp. This way, the server can verify the HMAC and timestamp before granting access, which prevents password interception and replay attacks. (2) Secondly, the timestamp T will be signed by an **HMAC (user_secret, T)**. With this timestamp, we can check if it’s within an acceptable window (example: last 5 minutes). A valid HMAC is generated **using user_secret**. However, if the timestamp is expired or the HMAC is invalid, the request will not be accepted, which makes sure that the attacker cannot use the old request to manipulate the **authentication**. (3) To further expand our security systems with integrity and authenticity, each log entry is signed with an **HMAC (user_secret, log_entry + prev_hmac)**. The client needs to refresh the session with new timestamps. This will ensure log integrity, prevent forgery, and block unauthorized session reuse. 

