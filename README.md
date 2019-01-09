# PHP Security Cheatsheet
This is a continuously updated listing of PHP-based countermeasures against certain types of vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Cross-Site Scripting](#cross-site-scripting)
- [Directory Traversal](#file-inclusion)
- [File Inclusion](#file-inclusion)
- [HTTP Header Injection](#http-header-injection)
- [HTTP Header Parameter Injection](#http-header-parameter-injection)
- [HTTP Response Splitting](#http-header-injection)
- [Information Disclosure](#information-disclosure)
- [Insecure Random Values](#insecure-random-values)
- [Template Injection](#template-injection)
- [UI Redressing](#ui-redressing)

# Cross-Site Request Forgery
### Anti-CSRF Tokens
You can use the [random_bytes](https://secure.php.net/manual/en/function.random-bytes.php) function to generate a cryptographically secure pseudo-random token. The following example describes a proof of concept implementation in
which the Anti-CSRF tokens are stored in the `$_SESSION` variable. The [bin2hex](https://secure.php.net/manual/en/function.bin2hex.php) function will be used in order to 
prevent issues with the character representation of non-character bytes returned by `random_bytes`.

```php
session_start();

$tokenLength = 64;

$_SESSION["CSRF_TOKEN"] = bin2hex(random_bytes($tokenLength));
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
```

### Enforce CORS Preflight with Custom Headers
If a HTTP request contains a custom header, the Browser will send a [CORS preflight request](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests) before it continues to send the original request. If no CORS policy has been set on the server, requests coming from another origin will fail. 

You can enforce this situation by checking for the existence of a custom HTTP request header in the list of headers returned by [apache_request_headers](https://secure.php.net/manual/en/function.apache-request-headers.php). 

```php
$requestHeaders = apache_request_headers();
if($requestHeaders !== false && 
   array_key_exists("X-Custom", $requestHeaders)){
   // Move on with request processing   
}
```

This technique should not be the main line of defense against CSRF attacks as there have been vulnerabilities in the past that enabled the sending of cross-site requests containing arbitrary HTTP request headers ([CVE-2017-0140](https://www.securify.nl/advisory/SFY20170101/microsoft-edge-fetch-api-allows-setting-of-arbitrary-request-headers.html)). There is no guarantee that this cannot happen again in the future.

### SameSite Cookie Attribute
The support of the SameSite cookie attribute was introduced in [PHP 7.3](https://wiki.php.net/rfc/same-site-cookie).

```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```

However, since this cookie attribute is relatively new, some older browser versions [do not support or only partially support](https://caniuse.com/#feat=same-site-cookie-attribute) this cookie attribute.

Be also aware that the SameSite cookie attribute won't prevent request forgery attacks that occur on-site ([OSRF](https://portswigger.net/blog/on-site-request-forgery)).

# Cross-Site Scripting
> Server-side countermeasures will not be enough to prevent XSS attacks as certain types of XSS, such as DOM-based XSS, 
> are the results of flaws in the client-side code. In case of DOM-based XSS, I recommend to use [DOMPurify](https://github.com/cure53/DOMPurify) and 
> to take a look at the [DOM-based XSS Prevention Cheatsheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet). Furthermore, you should also follow the development of [Trusted Types for DOM Manipulation](https://github.com/WICG/trusted-types).

### Automatic Context-Aware Escaping
Automatic context-aware escaping should be your main line of defense against XSS attacks. Personally, I recommend using the [Latte](https://latte.nette.org/en/guide#toc-context-aware-escaping) template engine as it covers various contexts such as HTML element, HTML attribute and the href attribute of an anchor element.

### Manual Context-Aware Escaping
###### Context: Inside a HTML element and HTML element attribute
[htmlentities](https://secure.php.net/manual/en/function.htmlentities.php) encodes all characters which have a reference in a specified HTML entity set. 

```php
$escapedString = htmlentities("<script>alert('xss');</script>", ENT_QUOTES | ENT_HTML5, "UTF-8", true);
```

The `ENT_QUOTES` flag makes sure that both single and double quotes will be encoded since the default flag does not encode single quotes. The `ENT_HTML5` flag encodes characters to their referenced entities in the [HTML5 entity set](https://www.quackit.com/character_sets/html5_entities/). Using the HTML5 entity set has the advantage that most of the special characters will be encoded as well in comparsion to the entity set defined by the default flag (`ENT_HTML401`).

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

The default flag won't protect you sufficiently if you forget to enclose your HTML attributes in single
or double quotes. For example, the htmlentities function won't encode the characters of the following XSS 
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

Regardless of the flag you set, always enclose HTML attributes in single or double quotes. 

With the third parameter of the htmlentities function, the target character set is specified. The value of 
this parameter should be equal to the character set defined in the target HTML document (e.g. UTF-8). 

Finally, the fourth parameter prevents double escaping if set to true.

###### Context: User-provided URLs
User-provided URLs should not beginn with the JavaScript pseudo protocol (`javascript`). This can be prevented by accepting only URLs that beginn with the HTTP (`http`) or HTTPS (`https`) protocol.

```php
if(substr($url, 0, strlen("http")) === "http" ||
   substr($url, 0, strlen("https")) === "https"){
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

### X-XSS-Protection Header
The [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection) header nables and configures XSS filtering available in some Browsers. Without the `mode=block` parameter, the Browser will render the page after it has been sanitized. 

```php
header("X-XSS-Protection: 1; mode=block");
```

# File Inclusion
The user should not have the possibility to control parameters that include files from the local filesystem or from a remote host. If this behavior cannot be changed, apply parameter whitelisting such that only valid parameters are accepted. This will also prevent attackers from traversing through the local file system.

```php
$parameterWhitelist = ["preview", "gallery"];
// Activate type checking of the needle-parameter by setting 
// the third parameter of the in_array function to true
if(in_array($parameter, $parameterWhitelist, true)){
    include($parameter . ".php");
}
```

# HTTP Header Injection
The [header](https://secure.php.net/manual/en/function.header.php) function prevents the injection of multiple headers since PHP 5.1.2 (see [Changelog](https://secure.php.net/manual/en/function.header.php) at the bottom).

# HTTP Header Parameter Injection
User-provided header parameters should be avoided if possible. If it can't be avoided, consider a whitelist approach to accept only specific values. The following sample shows how to prevent unvalidated redirection attacks with a whitelist of valid locations.

```php
$parameterWhitelist = ["ManagementPanel", "Dashboard"];
// Activate type checking of the needle-parameter by setting 
// the third parameter of the in_array function to true
if(in_array($parameter, $parameterWhitelist, true)){
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
# Insecure Random Values
### Pseudo-Random Bytes
The [random_bytes](https://secure.php.net/manual/en/function.random-bytes.php) functions generates an arbitrary length string of pseudo-random bytes which are secure for cryptographic use.

```php
string random_bytes ( int $length )
```

### Pseudo-Random Integers
The [random_int](https://secure.php.net/manual/en/function.random-int.php) functions generates a pseudo-random integer which is secure for cryptographic use.

```php
int random_int ( int $min , int $max )
```

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
