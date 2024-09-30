# ANZ-Cyber-Security-Management-Virtual-Experience-Program 


## Objective
The primary objective of the project was to simulate real-world scenarios encountered by cybersecurity professionals in a large financial institution. This experience focused on investigating potential cyber threats, identifying indicators of compromise, and providing well-documented remediation steps. The tasks were designed to develop investigative, analytical, and reporting skills critical to managing cybersecurity incidents. The program consists of two tasks: a social engineering investigation and a digital investigation.



### Skills Learned
- Social Engineering Awareness: Identifying red flags in email content, sender information, and attachment/link behavior. Applying knowledge of common social engineering tactics like phishing.

- Email Analysis: Scrutinizing email headers, sender legitimacy, and attachment types. Understanding how to analyze email content for suspicious elements.

- Digital Forensics: Examining network traffic captured in a pcap file. Identifying user activity based on network data packets. Documenting investigation steps and findings.

- Incident Response & Reporting: Enhanced capability to write clear, technical reports that translate complex security incidents into actionable recommendations for mitigation.

- Network Security: Identifying malicious activity through network traffic analysis and forensic investigation.


### Tools Used

- Wireshark: Used for detailed packet capture (pcap) file analysis and network traffic investigation.
- Hex Fiend: to see the raw and exact contents of a file.
- Email Header Analysis Tools: To investigate sender metadata and detect spoofing or phishing indicators.
- Phishing Detection Techniques: Applied manual and automated methods to assess email authenticity and safety.

## Steps
Task1 - Social Engineering Investigation - You have been assigned a set of emails to investigate, and your task is to determine whether each email is malicious or safe. If you identify any emails as malicious, you will need to write a concise report explaining the reasons behind your conclusion. This report should include details such as suspicious content, malicious attachments or links, abnormal sender information, or other indicators of compromise like phishing attempts or malware. The goal is to efficiently analyze the emails and report any threats promptly to ensure timely mitigation.

-To verify that a website was a safe and genuine ANZ page, I ensured that it had a secure Socket Layer (SSL) Certificate. I checked the browser’s address bar to confirm that the website address had changed from http:// to https://, indicating a secure connection. Additionally, I looked for a security icon resembling a lock or key near the address bar on pages requiring security credentials. By clicking on the icon, I accessed more detailed information about ANZ's SSL Certificate, confirming the site's authenticity and security.

Also, this is worth the read. [How to stay safe online.](https://www.anz.com.au/security/protect-yourself/online/) 

Below are the 7 emails we took to investigate whether they are safe or not.

*Ref 1.1: Email-1*
<img width="930" alt="T1-Email1" src="https://github.com/user-attachments/assets/2bcd0513-4037-4297-9423-244c28a076bb">



Analysis:
- Safe or Malicious: **Safe**
-	It’s clearly not spam as the reply indicates a previous relationship and that the email was expected and welcome. The date and time could indicate that the conversation was anticipated, as there is next to no delay in a reply.
- This email is non malicious. It’s a typical conversation between friends and contains no potentially dangerous artefacts. 




*Ref 1.2: Email-2*
<img width="930" alt="T1-Email2" src="https://github.com/user-attachments/assets/f70c7938-979c-4ddc-9d2e-088551aacfe4">



Analysis:
- Safe or Malicious: **Malicious**
- The email claims to be from one drive but the email sender is from a Russian domain which is well known for malicious emails.
- The email tries to get the user to download a file, without providing information about the file’s content, or the sender.  
- The email’s format is unprofessional and contains poor grammar & spelling. Y
- You would not expect an email from an official Microsoft service to be formatted and presented like this. 



*Ref 1.3: Email-3*
<img width="930" alt="T1-Email3" src="https://github.com/user-attachments/assets/047246a5-5e4b-4bed-b202-7394cb2a2c9e">



Analysis:
- Safe or Malicious: **Malicious**
- The email is presented as a question from a friend who cannot access Facebook, and asks the recipient to follow a link to see if Facebook is working for them. But the link provided is actually a phishing link make to look like facebook.com at first glance.
- The senders account could be compromised, so a malicious email like this could still come from a trusted friends account.



*Ref 1.4: Email-4*
<img width="930" alt="T1-Email4" src="https://github.com/user-attachments/assets/39fccd1c-132b-482a-815a-75adebc227c6">



Analysis:
- Safe or Malicious: **Safe**
- This email is an example of generic marketing, it could be regarded as Spam (unwanted or unrequested marketing content). It’s been forwarded twice, but the original sender is a mass mail service.
- If googled, the site can be seen as a sales site that contains no malicious content.
- The email contains no links or requests for information, just pure advertising.



*Ref 1.5: Email-5*
<img width="930" alt="T1-Email5" src="https://github.com/user-attachments/assets/6d23a4d4-b141-414b-85c0-39848abc8956">



Analysis:
- Safe or Malicious: **Malicious**
- The email is requesting the recipient’s credentials for unusual reasons. They’ve tried to make the issue seem urgent, which is a well-known persuasive technique often used for phishing. 
- The email lacks professionalism which gives more reason to believe it’s a fake. 
- Legitimate users/services would not ask for account details. This is almost always a sign of malicious activity. 



*Ref 1.6: Email-6*
<img width="930" alt="T1-Email6" src="https://github.com/user-attachments/assets/a8401f46-59b8-4622-98d0-8c8dd84b4e9d">



Analysis:
- Safe or Malicious: **Safe**
- This email is non malicious. It is a typical workplace email. There are no files, links or suspicious requests within the emails, and for the most part internal work emails can be trusted to be safe.
- The senders email address matches the name on the signature, and appears to be well formatted and professional. 



*Ref 1.7: Email-7*


<img width="600" alt="T1-Email7" src="https://github.com/user-attachments/assets/50396cf5-c26d-4cea-8126-73498b88f11d">



Analysis:
- Safe or Malicious: **Malicious**
- The email claims to be from Geico Insurance but the sender doesn’t have an official Geico email address, and the URL provided is not linked to Geico in any way. 
- The email sender claims to be someone called "Mike Ferris", but the display name of the sender is Val.kill.ma. 
- Legitimate companies would use HTTPS for any financial transactions. The link provided is just http, which is another indicator that this is a fake. HTTPS is secured and encrypted where as HTTP is not. 

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Task 2 - Digital Investigation - Suspicious network activity has been detected from a user on the ANZ network. A laptop has been flagged in our security systems due to unusual internet traffic, and you have been tasked with investigating the network traffic to determine what the user accessed and downloaded. Your responsibility is to examine the provided packet capture (pcap) file containing the user's recent network activity and identify any images viewed, files accessed, and other artifacts within the data. You will be expected to report on all findings and document the steps and processes followed during the investigation.

-First of all, I opened the pcap file in wireshark. Then, I filtered the traffic for 'http' only. This view let me see some interesting http GET requests, which indicated that the user specifically requested information.

*Ref 2.0: Wireshark*
<img width="966" alt="T2-Wireshark0" src="https://github.com/user-attachments/assets/0327be9f-191f-4d90-ab80-5529dcd43e98">

--->Now, we begin the investigation with anz-logo.jpg.

*Ref 2.1: Wireshark*
<img width="1075" alt="T2-Wireshark1" src="https://github.com/user-attachments/assets/28ec9661-1e33-45e8-8c20-586ef573b86d">


To investigate this image download further, I viewed its TCP stream to see what I could find.

*Ref 2.2: Wireshark*
<img width="1440" alt="T2-Wireshark2" src="https://github.com/user-attachments/assets/e5515ec2-9b0d-47d3-aee9-d1b755493170">


Looking through the data in the TCP stream showed that  the data contained two headers and a footers for a .jpg image. The header/footer is FFD8 – FFD9 in hex and the images are also recognizeable in ASCII by the string ‘JFIF’ near the start.

*Ref 2.3: Wireshark*
<img width="1440" alt="T2-Wireshark3" src="https://github.com/user-attachments/assets/882b7731-31fa-4571-837b-3902f8dfb160">


The next step taken was carving out the images from the tcp stream, which I did by taking all the hex from FFD8 to FFD9 and copying it into the hex editor program Hex Fiend.

*Ref 2.4: Hex Fiend*
<img width="900" alt="T2-Hexfiend" src="https://github.com/user-attachments/assets/9c5f825a-e8d2-4c5a-9195-87efd646ec69">



I then saved the file as a jpg and opened it, resulting in the image below. 

*Ref 2.5: ANZ Logo*


<img width="400" alt="image" src="https://github.com/user-attachments/assets/c0548be1-2f56-474f-b326-c92600fb2737">







--->Then I followed the above same procedures for bank-card.jpg resulting in the image of bank-card. 



*Ref 2.6: Wireshark*
<img width="1440" alt="T2-Wireshark4" src="https://github.com/user-attachments/assets/d2d98c55-17cb-47ff-9e66-ffd6e48883b4">




*Ref 2.7: Bank-Card*


<img width="400" alt="image" src="https://github.com/user-attachments/assets/00191daf-86b4-4600-9cb9-f467d43eff7f">


--->Next, I did same with ANZ1.jpg and ANZ2.jpg and retrieved the following image. 

*Ref 2.8: ANZ1*

<img width="219" alt="image" src="https://github.com/user-attachments/assets/98ea5e66-b205-46ca-b8d1-e130e513178e">

*Ref 2.9: ANZ2*

<img width="223" alt="image" src="https://github.com/user-attachments/assets/f904fa88-c985-4e7b-905e-1925b879451e">


But when I followed the TCP stream and view the data as ASCII for ANZ1 and ANZ2, there were hidden messages as well inside data at the end of image. 
It said _”You've found a hidden message in this file! Include it in your write up.”!_ and _“You've found the hidden message! Images are sometimes more than they appear.”_



*Ref 2.10: Wireshark*
<img width="1440" alt="T2-Wireshark5" src="https://github.com/user-attachments/assets/58a1d364-afc5-4e12-9ca7-db33cc564b47">

*Ref 2.11: Wireshark*
<img width="1440" alt="T2-Wireshark6" src="https://github.com/user-attachments/assets/4c088f4e-09ec-4973-8e56-390fa41da3d1">


--->Next, I followed "how-to-commit-crimes.docx". 

*Ref 2.12: Wireshark*
<img width="1440" alt="T2-Wireshark7" src="https://github.com/user-attachments/assets/1fcd52ef-da9a-45ce-bc0b-3f0741172ef8">

The Ascii view showed the following  message:

“Step 1: Find target

Step 2: Hack them

This is a suspicious document.

*Ref 2.13: Wireshark*
<img width="1407" alt="T2-Wireshark8" src="https://github.com/user-attachments/assets/f46214ef-087d-499a-b78b-9aaaac6cec28">

--->Next, I investigated the 3 pdf documents: ANZ_Document.pdf, ANZ_Document2.pdf, evil.pdf

It was a pdf document so, the hex signature was found to be “25 50 44 46”. So ,I copied all the data to the end beginning with this and got the following results:

*Ref 2.14: ANZ_Document.pdf*
<img width="1440" alt="T2-ANZ_Document" src="https://github.com/user-attachments/assets/29275e02-5df7-4798-b59f-63f94442c43c">

*Ref 2.15: ANZ_Document2.pdf*
<img width="1440" alt="T2-ANZ_Document2" src="https://github.com/user-attachments/assets/63a89fae-6f94-43ee-b711-06535f0ab14e">

*Ref 2.16: evil.pdf*
<img width="1331" alt="T2-Evil" src="https://github.com/user-attachments/assets/703abc9a-86ca-4474-9639-fd96125f1642">


--->Afterwards, I investigated "hiddenmessage2.txt". It had encoded data when viewed with hex and had same hex signature as jpg image.

*Ref 2.17: hiddenmessage2*

<img width="452" alt="image" src="https://github.com/user-attachments/assets/037836cf-f7db-4568-9b46-5a4929302c6a">

--->Then,I investigated "atm-image.jpg"There were two sets of file signature. When I extracted two sets of data,I got two jpg images.
Here,a single GET request by user downloaded two images.

*Ref 2.18: atm-image*

<img width="243" alt="image" src="https://github.com/user-attachments/assets/3a3fafff-e801-488b-9bf1-80f5d9fcdcad">



*Ref 2.19: hidden inside atm-image*

<img width="200" alt="image" src="https://github.com/user-attachments/assets/b14a84c3-bd8b-4b33-a256-6928d188ae38">

--->Next, I investigated "broken.png". It did not respond on png hex signature. Then I realised that the data was encoded in base64. I decrypted the base64 with online tool. After decryption, we got png image data . The image data was further copied in hex and found following image.

*Ref 2.20: broken.png*

<img width="600" alt="image" src="https://github.com/user-attachments/assets/7952ca18-be34-4661-9698-f8522f2273c8">

--->Finally, I investigated securepdf.pdf. It was not a  PDF.IT had message; Password is “secure” at the bottom.
The bottom of the file contained the hidden message: Password is “secure”. It was a zip file so I. used the hex signature 504B0304.
it contained a pdf file called rawpdf.pdf. When opened, the pdf asked for a password. The password ‘secure’ shown in the tcp stream worked, and the PDF opened. 

*Ref 2.21: securepdf.pdf*


<img width="600" alt="image" src="https://github.com/user-attachments/assets/16bc524b-4f24-4dfd-a683-7e6bbad8cba5">



 ## Conclusion

 
Through this project, I developed a strong foundation in managing cybersecurity incidents, particularly in identifying and mitigating social engineering threats and suspicious network activities. The ability to investigate and document cybersecurity threats with a structured and methodical approach has reinforced my incident response skills. This experience has prepared me for real-world cybersecurity challenges by giving me the tools to proactively address potential threats and protect sensitive data in a professional setting.


