# PHP Security Cheatsheet
This is a summary of PHP-based countermeasures against certain vulnerabilities

## Table of Content
- [Cross-Site Request Forgery](#cross-site-request-forgery)

# Cross-Site Request Forgery 
### SameSite Cookie Attribute
The SameSite cookie attribute is supported in [PHP >= 7.3](https://wiki.php.net/rfc/same-site-cookie)
```php
bool setcookie ( string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, 
string $domain = "" [, bool $secure = false [, bool $httponly = false [, string $samesite = "" 
]]]]]]] )
```
