# PHP Security Cheatsheet
This is a continuously updated listing of PHP-based countermeasures against certain types of vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Cross-Site Scripting](#cross-site-scripting)
- [Cryptographically Secure Pseudo-Random Values](#cryptographically-secure-pseudo-random-values)
- [Directory Traversal](#file-inclusion)
- [File Inclusion](#file-inclusion)
- [HTTP Header Injection](#http-header-injection)
- [HTTP Header Parameter Injection](#http-header-parameter-injection)
- [HTTP Response Splitting](#http-header-injection)
- [HTTP Security Headers](#http-security-headers)
- [Information Disclosure](#information-disclosure)
- [UI Redressing](#ui-redressing)

# Cross-Site Request Forgery
### SameSite Cookie Attribute
The SameSite cookie attribute is supported in [PHP >= 7.3](https://wiki.php.net/rfc/same-site-cookie).

```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```

# Cross-Site Scripting
### Manual Context-Aware Escaping
###### Context: Inside a HTML element and HTML element attribute
[htmlentities](https://secure.php.net/manual/en/function.htmlentities.php) encodes all characters which have a reference in a specified HTML entity set. 

```php
$escapedString = htmlentities("<script>alert('xss');</script>", ENT_QUOTES | ENT_HTML5, "UTF-8", true);
```

The `ENT_QUOTES` flag makes sure that both single and double quotes will be encoded since the default flag does not encode single quotes. The `ENT_HTML5` flag encodes characters to their referenced entities in the [HTML5 entity set](https://www.quackit.com/character_sets/html5_entities/). Using the HTML5 entity set has the advantage that most of the special characters will be encoded as well in comparsion to the default flag (`ENT_HTML401`).

Special Characters:
``` 
+-#~_.,;:@€<§%&/()=?*'"°^[]{}\`´=<,|²³
```

Encoded with `ENT_HTML401` Flag (Default):
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
1 onmouseover=alert(1);
```

This payload can be used in a situation like the following:

```html
<div data-custom-attribute-value=1 onmouseover=alert(1);></div>
```

However, when the `ENT_HTML5` flag is used, the payload would not be usable
in the previously described situation:

```html
<div data-custom-attribute-value=1 onmouseover&equals;alert&lpar;1&rpar;&semi;></div>
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
The [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection) header nables and configures XSS filtering available in some Browsers. Without the mode=block parameter, the Browser will render the page after it has been sanitized. 

```php
header("X-XSS-Protection: 1; mode=block");
```

# Cryptographically Secure Pseudo-Random Values
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

# HTTP Security Headers
The [header](https://secure.php.net/manual/en/function.header.php) function can be used to specify security headers. The following table lists the supported security headers:

| Security Header  | Description |
| ------------- | ------------- |
| [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)  | Defines a whitelist of trusted sources for resources such as images or scripts |
| [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)  | Forces a browser to access a website only via HTTPS  |
| [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) | Controls the content of the Referrer header  |
| [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT) | Determines if your website is ready for [Certificate Transparency](https://www.certificate-transparency.org/) (CT) and enforces it if it is  |
| [Feature-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy) | Allows or disallows the use of certain Web APIs such as the Geolocation API  |

# Information Disclosure
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

# UI Redressing
To prevent UI redressing attacks such as Clickjacking, prohibit a malicious website from embedding your website in a frame by using the [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) header.

```php
header("X-Frame-Options: deny");
```
