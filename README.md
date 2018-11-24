# PHP Security Cheatsheet
This is a summary of PHP-based countermeasures against certain vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [Cross-Site Scripting](#cross-site-scripting)
- [HTTP Security Headers](#http-security-headers)

# Cross-Site Request Forgery
### SameSite Cookie Attribute
The SameSite cookie attribute is supported in [PHP >= 7.3](https://wiki.php.net/rfc/same-site-cookie)
```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```
# Cross-Site Scripting
### Context-Aware Escaping
###### Context: HTML Element
[htmlspecialchars](https://secure.php.net/manual/en/function.htmlspecialchars.php) escapes special HTML characters such as <,>,&," and ' which can be used to build XSS payloads. 
The ENT_QUOTES flag makes sure that both single and double quotes will be escaped
```php
$escapedString = htmlspecialchars("<script>alert('xss');</script>", ENT_QUOTES);
```

# HTTP Security Headers
The [header](https://secure.php.net/manual/de/function.header.php) function can be used to specify security headers. The following table lists the supported
security headers:

| Security Header  | Description |
| ------------- | ------------- |
| [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)  | Defines a whitelist of trusted sources for resources such as images or scripts |
| [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)  | Forces a browser to access a website only via HTTPS  |
| [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) | Controls the content of the Referrer header  |
| [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT) | Determines if your website is ready for Certificate Transparency (CT) and enforces it if it is  |
| [Feature-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy) | Allows or disallows the use of certain Web APIs such as the Geolocation API  |
| [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)  | Enables and configures XSS filtering available in some Browsers  |

```php
// Enable XSS filtering and block any detected XSS attacks
header("X-XSS-Protection: 1; mode=block");
```
