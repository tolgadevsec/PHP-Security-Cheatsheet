# PHP Security Cheatsheet
This is a summary of PHP-based countermeasures against certain vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)

# Cross-Site Request Forgery 
### SameSite Cookie Attribute

```
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" ]]]]]]] )
```
