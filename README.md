# PHP Security Cheatsheet
This cheatsheet is an overview of techniques to prevent common vulnerabilities within PHP web applications.  

> All of the examples presented in this cheatsheet are for learning and experimentation purposes and are not meant to be used in a production system. Most of the techniques and countermeasures are already built-in in many modern web application frameworks and should be taken advantage of.

## Articles, Tutorials, Guides and Cheatsheets
In case you are keen on learning more about PHP security, you can check out the following resources:
- [The 2018 Guide to Building Secure PHP Software](https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software)
- [PHP: The Right Way - Security](https://phptherightway.com/#security)
- [Survive The Deep End: PHP Security](https://phpsecurity.readthedocs.io/en/latest/)
- [PHP Configuration Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [Awesome PHP Security](https://github.com/guardrailsio/awesome-php-security)
- [PHP RFC: Is Literal Check](https://github.com/craigfrancis/php-is-literal-rfc)

## Table of Vulnerabilities
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Cross-Site Scripting](#cross-site-scripting)
- [Directory Traversal](#file-inclusion)
- [File Inclusion](#file-inclusion)
- [HTTP Header Injection](#http-header-injection)
- [HTTP Header Parameter Injection](#http-header-parameter-injection)
- [HTTP Response Splitting](#http-header-injection)
- [Information Disclosure](#information-disclosure)
- [Insecure Password Storage and Hashing](#insecure-password-storage-and-hashing)
- [Insecure Random Values](#insecure-random-values)
- [SQL Injection](#sql-injection)
- [Template Injection](#template-injection)
- [UI Redressing](#ui-redressing)
- [Using Packages With Known Vulnerabilities](#using-packages-with-known-vulnerabilities)

# Cross-Site Request Forgery
> Before going into any of the following countermeasures, it is important to know the concept of [safe HTTP methods](https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP). A HTTP method is considered safe if it is not changing any state on the server-side of a web application or service. HTTP methods such as GET should therefore not be used to, e.g., remove a resource on the server-side. Otherwhise, this would make it possible, if no CSRF countermeasures are in place, to lure a victim to a attacker-controlled website which sends a HTTP GET request (e.g. `GET /delete/:id`) when the website is loaded - and removes a resource using the victim's session.

> If a HTTP request contains a custom header, the Browser will send a [CORS preflight request](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests) before it continues to send the original request. If no CORS policy has been set on the server, requests coming from another origin will fail. You can enforce this situation by checking for the existence of a custom HTTP request header (e.g. `X-CSRF-Token`) in the list of headers returned by [apache_request_headers](https://secure.php.net/manual/en/function.apache-request-headers.php). However, being able to set arbitrary request headers might still be possible due to vulnerabilities such as ([CVE-2017-0140](https://www.securify.nl/advisory/SFY20170101/microsoft-edge-fetch-api-allows-setting-of-arbitrary-request-headers.html)).

### Anti-CSRF Tokens
You can use the [random_bytes](https://secure.php.net/manual/en/function.random-bytes.php) function to generate a cryptographically secure pseudo-random token. The following example describes a basic proof of concept in
which a Anti-CSRF token is delivered to the client in a custom HTTP response header (`X-CSRF-Token`). The [bin2hex](https://secure.php.net/manual/en/function.bin2hex.php) function will be used in order to 
prevent issues with the character representation of non-character bytes returned by `random_bytes`.

```php
session_start();

$tokenLength = 64;

$_SESSION["CSRF_TOKEN"] = bin2hex(random_bytes($tokenLength));

header("X-CSRF-Token: " . $_SESSION["CSRF_TOKEN"]);

// ...
```

Instead of simply comparing two values and their data types with `===`, the [hash_equals](https://secure.php.net/manual/en/function.hash-equals.php) function is used to prevent timing attacks against string comparisons. Have a look at this article on [timing attacks](https://blog.ircmaxell.com/2014/11/its-all-about-time.html) for further details.

```php
$serverToken = $_SESSION["CSRF_TOKEN"];
$requestHeaders = apache_request_headers();

if($requestHeaders !== false &&
   array_key_exists("X-CSRF-Token", $requestHeaders)){
   
   $clientToken = $requestHeaders["X-CSRF-Token"];
   
   if(hash_equals($serverToken, $clientToken)){
      // Move on with request processing
   }
}
else {
    // Do not continue with request processing
    exit;
}
```

### SameSite Cookie Attribute
The support of the SameSite cookie attribute was introduced in [PHP 7.3](https://wiki.php.net/rfc/same-site-cookie).

```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```

> The SameSite cookie attribute won't prevent request forgery attacks that occur on-site ([OSRF](https://portswigger.net/blog/on-site-request-forgery)). However, this type of request forgery is not so common and can be prevented with Anti-CSRF tokens as well. 

# Cross-Site Scripting
> Server-side countermeasures will not be enough to prevent XSS attacks as certain types of XSS, such as DOM-based XSS, 
> are the results of flaws in the client-side code. In case of DOM-based XSS, I recommend to use [DOMPurify](https://github.com/cure53/DOMPurify) and 
> to take a look at the [DOM-based XSS Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html). Furthermore, you should also follow the development of [Trusted Types for DOM Manipulation](https://github.com/WICG/trusted-types) - See [
Trusted Types help prevent Cross-Site Scripting](https://developers.google.com/web/updates/2019/02/trusted-types) for a recent article on that topic.

### Automatic Context-Aware Escaping
Automatic context-aware escaping should be your main line of defense against XSS attacks. Personally, I recommend using the [Latte](https://latte.nette.org/en/guide#toc-context-aware-escaping) template engine as it covers various contexts such as HTML element, HTML attribute and the href attribute of an anchor element.

### Manual Context-Aware Escaping
###### Context: Inside a HTML element and HTML element attribute
[htmlentities](https://secure.php.net/manual/en/function.htmlentities.php) encodes all characters which have a reference in a specified HTML entity set. 

```php
$escapedString = htmlentities("<script>alert('xss');</script>", ENT_QUOTES | ENT_HTML5, "UTF-8", true);
```

The `ENT_QUOTES` flag makes sure that both single and double quotes will be encoded since the default flag does not encode single quotes. The `ENT_HTML5` flag encodes characters to their referenced entities in the [HTML5 entity set](https://dev.w3.org/html5/html-author/charref). Using the HTML5 entity set has the advantage that most of the special characters will be encoded as well in comparsion to the entity set defined by the default flag (`ENT_HTML401`).

Special Characters:
``` 
+-#~_.,;:@€<§%&/()=?*'"°^[]{}\`´=<,|²³
```

Encoded with `ENT_HTML401` Flag:
```
+-#~_.,;:@&euro;&lt;&sect;%&amp;/()=?*&#039;&quot;&deg;^[]{}\`&acute;=&lt;,|&sup2;&sup3;
```

Encoded with `ENT_HTML5` Flag:
```
&plus;-&num;~&lowbar;&period;&comma;&semi;&colon;&commat;&euro;&lt;&sect;&percnt;&amp;&sol;
&lpar;&rpar;&equals;&quest;&ast;&apos;&quot;&deg;&Hat;&lbrack;&rsqb;&lbrace;&rcub;&bsol;&grave;
&DiacriticalAcute;&equals;&lt;&comma;&vert;&sup2;&sup3;
```

The default flag won't protect you sufficiently if you forget to enclose your HTML attributes in **single quotes**
or **double quotes**. For example, the `htmlentities` function won't encode the characters of the following XSS 
payload:

```
1 onmouseover=alert(1)
```

This payload can be used in a situation like the following:

```html
<div data-custom-attribute-value=1 onmouseover=alert(1)></div>
```

However, with the `ENT_HTML5` flag, the payload would not be usable
in the previously described situation:

```html
<div data-custom-attribute-value=1 onmouseover&equals;alert&lpar;1&rpar;></div>
```

Regardless of the flag you set, **always** enclose HTML attributes in **single quotes** or **double quotes**. 

With the third parameter of the `htmlentities` function, the target character set is specified. The value of 
this parameter should be equal to the character set defined in the target HTML document (e.g. UTF-8). 

Finally, the fourth parameter prevents double escaping if set to true.

###### Context: User-provided URLs
User-provided URLs should not beginn with the JavaScript (`javascript:`) or a data (`data:`) URI scheme. This can be prevented by accepting only URLs that beginn with the HTTPS (`https`) protocol.

```php
if(substr($url, 0, strlen("https")) === "https"){
   // Accept and process URL
}
```
###### Context: Inside a script element or inline event handler
PHP does not provide a native function to escape user input in a JavaScript context. The following code snippet is from the [Escaper Component](https://github.com/zendframework/zend-escaper/blob/master/src/Escaper.php) of the Zend Framework which implements JavaScript context escaping. 

```php
 /**
  * Escape a string for the Javascript context. This does not use json_encode(). An extended
  * set of characters are escaped beyond ECMAScript's rules for Javascript literal string
  * escaping in order to prevent misinterpretation of Javascript as HTML leading to the
  * injection of special characters and entities. The escaping used should be tolerant
  * of cases where HTML escaping was not applied on top of Javascript escaping correctly.
  * Backslash escaping is not used as it still leaves the escaped character as-is and so
  * is not useful in a HTML context.
  *
  * @param string $string
  * @return string
  */
 public function escapeJs($string)
 {
     $string = $this->toUtf8($string);
     if ($string === '' || ctype_digit($string)) {
         return $string;
     }
     $result = preg_replace_callback('/[^a-z0-9,\._]/iSu', $this->jsMatcher, $string);
     return $this->fromUtf8($result);
 }
```
```php
 /**
  * Callback function for preg_replace_callback that applies Javascript
  * escaping to all matches.
  *
  * @param array $matches
  * @return string
  */
 protected function jsMatcher($matches)
 {
     $chr = $matches[0];
     if (strlen($chr) == 1) {
         return sprintf('\\x%02X', ord($chr));
     }
     $chr = $this->convertEncoding($chr, 'UTF-16BE', 'UTF-8');
     $hex = strtoupper(bin2hex($chr));
     if (strlen($hex) <= 4) {
         return sprintf('\\u%04s', $hex);
     }
     $highSurrogate = substr($hex, 0, 4);
     $lowSurrogate = substr($hex, 4, 4);
     return sprintf('\\u%04s\\u%04s', $highSurrogate, $lowSurrogate);
 }
```
The jsMatcher function escapes each character of the target string that matches the regular expression used in the `escapeJs` function (`[^a-z0-9,\._]/iSu`). The current character will be encoded in hexadecimal if it is not greater than one byte. Note that [strlen](https://secure.php.net/en/strlen) returns the number of bytes and not the number of characters (this is a documented behavior). 

Otherwise, the current character will be encoded in Unicode. Some characters can only be encoded in [UTF-16](https://en.wikipedia.org/wiki/UTF-16), using two 16-bit code units (referred as `$highSurrogate` and `$lowSurrogate` at the end of the `jsMatcher` function). This article on [JavaScript's internal character encoding](https://mathiasbynens.be/notes/javascript-encoding) will help you understand the details why certain characters need to be encoded in UTF-16.

### HTTPOnly Cookie Attribute
The HTTPOnly cookie attribute signals the Browser to prevent any client-side scripts from accessing data stored in a cookie. The intention behind this cookie attribute is to protect session identifiers within cookies from XSS attacks with a session hijacking payload. Please note that this cookie attribute does not prevent XSS attacks in general.

```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```

You can also set the HTTPOnly cookie attribute in your PHP configuration file using the [session.cookie_httponly](https://secure.php.net/manual/en/session.configuration.php#ini.session.cookie-httponly) parameter.

```
session.cookie_httponly = true
``` 

### Content Security Policy
Another effective defense against XSS attacks is to utilize a so called [Content Security Policy](https://developers.google.com/web/fundamentals/security/csp) (CSP). Essentially, a CSP is an acceptlist of trusted sources from which a web application (the frontend part) is allowed to download and render/execute content. A CSP could therefore prevent the exfiltration of data (e.g. session ID) to a source that is not in the acceptlist. 

In cases where an attacker cannot exfiltrate data but execute code, a CSP can still be beneficial as it provides mechanisms to prevent the execution of inline JavaScript code (unless `unsafe-inline` is explicitly specified as a trusted source). This, however, presumes an application architecture in which aspects such as the application's behavior and its appearance are separated (e.g. all JavaScript code are contained in .js files, all style instructions are cointained in .css files). If that should not be the case, you might be able to [use nonces to add inlined resources to the acceptlist](https://barryvanveen.nl/blog/47-how-to-prevent-the-use-of-unsafe-inline-in-csp).

A CSP is delivered to a Browser as a HTTP response header as shown below:

```php
// Starter Policy from https://content-security-policy.com/
header("Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';");
```

While the CSP in the example above is short and simple, it is not unusual to have a large CSP or a different CSP for specific pages. In such scenarios, it makes sense to make use of libraries such as the [CSP Builder](https://github.com/paragonie/csp-builder) to ease the integration and maintenance of CSPs.

> A CSP is a mitigation technique against XSS attacks, **it does not fix the vulnerability** through which an XSS attack has
> been executed. For that reason, a CSP should be rather seen as **a defense-in-depth strategy** on top of context-aware 
> escaping of user-controlled input, which is far more important. Furthermore, as with all mitigation techniques, CSPs can
> be bypassed with [Script Gadgets](https://github.com/google/security-research-pocs/tree/master/script-gadgets) 
> or by exploiting [common CSP mistakes](http://conference.hitb.org/hitbsecconf2016ams/materials/D1T2%20-%20Michele%20Spagnuolo%20and%20Lukas%20Weichselbaum%20-%20CSP%20Oddities.pdf) to name but a few examples. 

# File Inclusion
The user should not have the possibility to control parameters that include files from the local filesystem or from a remote host. If this behavior cannot be changed, apply parameter acceptlisting such that only valid parameters are accepted. This will also prevent attackers from traversing through the local file system.

```php
$parameterAcceptlist = ["preview", "gallery"];
// Activate type checking of the needle-parameter by setting 
// the third parameter of the in_array function to true
if(in_array($parameter, $parameterAcceptlist, true)){
    include($parameter . ".php");
}
```

# HTTP Header Injection
The [header](https://secure.php.net/manual/en/function.header.php) function prevents the injection of multiple headers since PHP 5.1.2 (see [Changelog](https://secure.php.net/manual/en/function.header.php) at the bottom).

# HTTP Header Parameter Injection
User-provided header parameters should be avoided if possible. If it can't be avoided, consider an acceptlist approach to accept only specific values. The following sample shows how to prevent unvalidated redirection attacks with an acceptlist of valid locations.

```php
$parameterAcceptlist = ["ManagementPanel", "Dashboard"];
// Activate type checking of the needle-parameter by setting 
// the third parameter of the in_array function to true
if(in_array($parameter, $parameterAcceptlist, true)){
    header("Location: /" . $parameter, true, 302);
    exit;
}
```
# Information Disclosure
### Error Messages
Many attacks against web applications exploit error messages to infer information on how the attack payload needs to be adjusted for a successful attack. Example attack techniques that utilize error messages are [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection) or a [Padding Oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack). For that reason, production systems should never display error messages. Instead, error messages should be logged using a library like [Monolog](https://github.com/Seldaek/monolog).

PHP provides the [display_errors](https://secure.php.net/manual/en/errorfunc.configuration.php#ini.display-errors) configuration parameter to determine if error messages should be part of the output. Use the value `off` to disable displaying any error messages.

```
display_errors = off
```
The same value should be applied for the [display_startup_errors](https://secure.php.net/manual/en/errorfunc.configuration.php#ini.display-startup-errors) configuration parameter which determines whether to display error messages that occur during PHP's startup sequence.

```
display_startup_errors = off
```

> It is also possible to set these configuration parameters at runtime with, e.g., `ini_set("display_errors", "off");`. 
> But it is not recommended as any fatal error would stop the execution of a PHP script and thus ignore the line with 
> the [ini_set](https://secure.php.net/manual/en/function.ini-set.php) function call.

Disabling the displaying of error messages should not be the primary defense against attacks like SQL Injection as there are other techniques such as [Blind SQL Injection](https://www.owasp.org/index.php/Blind_SQL_Injection) that do not necessarily rely on error messages.

### PHP Exposure
The following countermeasures are meant to hide the fact that your web application is built in PHP. Be aware that hiding this fact won't make existing vulnerabilities in your web application go away. It is rather meant as a countermeasure against the reconnaissance process of an attacker, where an attacker attempts to learn as much about a target system as possible. 

Obviously, the techniques in this section won't be of much use if functionalities of a web application are accessed by requests such as `/showImage.php?id=23` where the file extension exposes the technology in use. However, you can hide the file extension on the fly with [mod_rewrite](https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html) if you are serving your web application with the Apache web server. 

###### Rename PHP Session Name
The default session name is `PHPSESSID`, you can change this name by setting the [session.name](https://secure.php.net/manual/en/session.configuration.php#ini.session.name) parameter in your PHP configuration file.

```
session.name = "SESSION_IDENTITY"
```

###### Disable X-Powered-By Header
Setting the [expose_php](https://secure.php.net/manual/en/ini.core.php#ini.expose-php) parameter to `off` in your PHP configuration file will removed the X-Powered-By Header from any HTTP Response.

```
expose_php = off
```
# Insecure Password Storage and Hashing
It should be needless to say that passwords **should never be stored in clear text**. The best practice is to store the hash value of the password instead. PHP provides a built-in function for this purpose which is called [password_hash](https://www.php.net/manual/en/function.password-hash.php).  

```php
$clearTextPassword = $_POST["Password"];
$passwordHash = password_hash($clearTextPassword, PASSWORD_DEFAULT);
```

You can use the built-in [password_verify](https://www.php.net/manual/en/function.password-verify.php) function to verify a user-provided password. The `password_verify` function will also require the hash value that you stored and generated with the `password_hash`function.

```php
$clearTextPassword = $_POST["Password"];
if(password_verify($clearTextPassword, $passwordHash)){
   // Password is correct
}
```

# Insecure Random Values
### Pseudo-Random Bytes
The [random_bytes](https://secure.php.net/manual/en/function.random-bytes.php) function generates an arbitrary length string of pseudo-random bytes which are secure for cryptographic use.

```php
string random_bytes ( int $length )
```

### Pseudo-Random Integers
The [random_int](https://secure.php.net/manual/en/function.random-int.php) function generates a pseudo-random integer which is secure for cryptographic use.

```php
int random_int ( int $min , int $max )
```

# SQL Injection
This type of vulnerability affects applications that interact with a SQL database for data storage and processing. The vulnerability occurs when a SQL query is dynamically constructed with user-controlled input and the user-controlled input is neither sanitized nor escaped. The best practice to prevent SQL injection vulnerabilities is to process user-controlled input and the SQL query separately and this can be done by using prepared statements. The [PDO](https://www.php.net/manual/en/book.pdo.php) database abstraction layer in PHP enables prepared statements through the [prepare](https://www.php.net/manual/en/pdo.prepare.php) method of the [PDO](https://www.php.net/manual/en/class.pdo.php) class.

```php
// Init and connect to database / Instantiate a PDO object
// ...

// Read user credentials
$eMail = $_POST["Email"];
$passwordHash = password_hash($_POST["Password"], PASSWORD_DEFAULT);

// Read user record from database based on the provided user credentials
$statement = $pdo->prepare("SELECT * FROM Users WHERE Email = :eMail AND PasswordHash=:passwordHash");
$statement->execute(["eMail" => $eMail, "passwordHash" => $passwordHash]);
$user = $statement->fetch();
```
> Note that the SQL query in the previous example is constructed as a string because that is what the PDO prepare method expects. This way of constructing SQL queries should rather be the exception as it is prone to developer mistakes who could accidentally embed user-controlled input into the string. Object-Relational Mapper (ORM) like [Doctrine](https://www.doctrine-project.org/) can make such mistakes less likely and provide more usable interfaces to construct queries in a object-oriented manner.


# Template Injection
This type of vulnerability occurs when the target template is built at runtime and parts of the template are controlled by the user. Template engines provide functions to safely embed user-controlled input into a template, make use of them. The following code snippet shows an example where user input is safely embed in a [Smarty](https://www.smarty.net/) template. 

```php
// Replacing {$searchTerm} with $_GET["searchTerm"] in the next line
// would introduce a template injection vulnerability
$templateString = "You searched for: {$searchTerm}";

$smarty = new Smarty();
$smarty->assign("searchTerm", $_GET["searchTerm"]);
$smarty->display("string:" . $templateString);
```

If you want to learn more on template injection vulnerabilities and how they can lead to remote code execution, watch this talk on [server-side template injection](https://www.youtube.com/watch?v=3cT0uE7Y87s). 

> Template injection is not limited to server-side web technologies and can also occur on the client-side. 
> Have a look at this talk on [client-side template injection](https://www.youtube.com/watch?v=VDAAGm_HUQU).

# UI Redressing
To prevent UI redressing attacks such as Clickjacking, prohibit a malicious website from embedding your website in a frame by using the [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) header.

```php
header("X-Frame-Options: deny");
```
# Using Packages With Known Vulnerabilities
When you integrate third party packages in your application, typically via a package manager like [Composer](https://getcomposer.org/), you might not be aware of packages containing exploitable vulnerabilities. Apart
from staying up to date on vulnerabilities affecting the packages you use, you can also make use of security 
packages like the one from [Roave](https://github.com/Roave/SecurityAdvisories) which prevents you from 
installing known vulnerable packages in the first place. Roaves source for vulnerable PHP packages is the 
[PHP Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories).

> Have a look at [A9 - Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities.html) from the [OWASP Top 10](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/) project for further guidance. 
