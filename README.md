# PHP Security Cheatsheet
This is a summary of PHP-based countermeasures against certain vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Cross-Site Scripting](#cross-site-scripting)
- [Cryptographically Secure Pseudo-Random Values](#cryptographically-secure-pseudo-random-values)
- [HTTP Header Injection](#http-header-injection)
- [HTTP Header Parameter Injection](#http-header-parameter-injection)
- [HTTP Security Headers](#http-security-headers)
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
### Context-Aware Escaping
###### Context: Inside a HTML element
[htmlspecialchars](https://secure.php.net/manual/en/function.htmlspecialchars.php) escapes special HTML characters such as <,>,&," and ' which can be used to build XSS payloads. The ENT_QUOTES flag makes sure that both single and double quotes will be escaped.
```php
$escapedString = htmlspecialchars("<script>alert('xss');</script>", ENT_QUOTES);
```
###### Context: User-provided URLs
User-provided URLs should not beginn with the JavaScript pseudo protocol (javascript:). This can be prevented by accepting only URLs that beginn with the HTTP (http:) or HTTPS (https:) protocol
```php
if(substr($url, 0, strlen("http:")) === "http:" ||
   substr($url, 0, strlen("https:")) === "https:"){
   // Accept and process URL
}
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
The [header](https://secure.php.net/manual/en/function.header.php) function can be used to specify security headers. The following table lists the supported.
security headers:

| Security Header  | Description |
| ------------- | ------------- |
| [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)  | Defines a whitelist of trusted sources for resources such as images or scripts |
| [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)  | Forces a browser to access a website only via HTTPS  |
| [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) | Controls the content of the Referrer header  |
| [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT) | Determines if your website is ready for [Certificate Transparency](https://www.certificate-transparency.org/) (CT) and enforces it if it is  |
| [Feature-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy) | Allows or disallows the use of certain Web APIs such as the Geolocation API  |
| [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)  | Enables and configures XSS filtering available in some Browsers  |
| [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)  | Controls if a Browser is allowed to load a page inside a frame  |

```php
// Enable XSS filtering and block any detected XSS attacks
header("X-XSS-Protection: 1; mode=block");
```
# UI Redressing
To prevent UI redressing attacks such as Clickjacking, prohibit a malicious website from embedding your website in a frame by using the [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) header.
```php
header("X-Frame-Options: deny");
```
