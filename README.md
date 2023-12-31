# IDOR-IN
The **IDOR IN** is a security utility designed to detect and identify Insecure Direct Object Reference (IDOR) vulnerabilities in web applications. IDOR vulnerabilities occur when an application allows direct access or manipulation of sensitive objects or resources without proper authorization or access control. This can lead to unauthorized access, data exposure, and potentially malicious activities.

The** IDOR IN Scanner tool** works by systematically scanning a target web application and examining various endpoints, parameters, and data access points to identify potential IDOR vulnerabilities. It leverages techniques such as parameter fuzzing, payload injection, and response analysis to detect signs of insecure direct object references.

# Key Features::
**Endpoint Scanning:** The tool scans predefined or user-specified endpoints within the target application to identify potential IDOR vulnerabilities.
**Parameter Fuzzing:** It generates variations of common parameter names combined with alphanumeric characters to test for potential IDOR vulnerabilities.
**Payload Injection:** The tool injects test values and additional payloads into parameters to observe how the application handles the input, looking for indications of IDOR vulnerabilities.
**Response Analysis:** It analyzes the responses from the application, searching for unauthorized access or indications of exposed sensitive data.
**Spidering and Crawling:** The tool crawls the target application, exploring linked pages and associated endpoints to ensure comprehensive coverage during the scan.
**Method Testing:** It performs requests using different HTTP methods (GET, POST, PUT, DELETE) to evaluate the behavior of the application under various scenarios.
**Sensitive Data Detection:** The tool checks for access to sensitive endpoints and notifies when unauthorized access to sensitive data is detected.
**Reporting:** It provides detailed reports highlighting potential IDOR vulnerabilities, including the affected URLs, methods, and response status codes.
_The IDOR IN Scanner tool helps security professionals and developers identify and mitigate IDOR vulnerabilities, enhancing the overall security posture of web applications and protecting sensitive data from unauthorized access._

# [+]Tool Tested On:- 
- Termux
* Kali Linux

# [?]Requirements:-
- Active Internet Connection
- Termux Version Upto Date 
- Android 7 or higher
- Stable Internet Connection
- Required modules in requirements.txt
- Website Basics

# Installation Commands ~
 ```pkg install git -y   ```

 ```git clone https://github.com/GManOfficial/IDOR-IN```

 ```cd IDOR-IN```

 ```pip install -r requirements.txt```
 
 ```python3 idor_scanner.py```

# Usage     
  ![Screenshot_2023_06_22_11_03_58_72_84d3000e3f4017145260f7618db1d683](https://github.com/GManOfficial/IDOR-IN/assets/128127654/00c19df4-45da-4590-9041-0978ebf6798f)
  
    5. **Enter A URL To start the scanning process. Include https:// or http:// as shown in the image.**
    6.  **You Can Watch the Tutorial Here**
