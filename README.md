# Marco de trabajo para XSS Reflejado (Reflected XSS Framework)

![Anatomía de un ataque XSS](https://websitesecuritystore.com/wp-content/uploads/2021/07/cross-site-scripting-examples.svg)

>*Imagen tomada de: [Website Security Store](https://websitesecuritystore.com)*

Este repositorio contiene un marco de trabajo básico para la detección y explotación ética de vulnerabilidades de tipo **XSS reflejado**.

---

## ⚠️ Disclaimer

> Este proyecto es **exclusivamente para fines educativos** y de **pruebas en entornos controlados**.  
> No está permitido su uso en sistemas sin la debida autorización.  
> **Demo utilizada:** [http://testfire.net](http://testfire.net) con credenciales `admin:admin`  
> Esta aplicación está diseñada intencionalmente para tener fallas de seguridad.  
> *“This web application is purposely designed to have security vulnerabilities for educational and testing purposes.”*

---

## 1. Add Custom HTTP Headers in Burp Suite

```bash
# En Burp -> Proxy -> match/replace rule
# Añadir:
Type: Request header
Match: ^User-Agent.*$
Replace: X-Pentest: Kxss_PoC 
Comment: (empty)
```
```bash
#Auto-modified request
POST /update HTTP/2
Host: example.com
Content-Type: application/json
X-Pentest: Kxss_PoC 
Content-Length: 34

{
  "key1": "value1",
  "key2": "value2"
}
```
>*Recurso: [Requestly](https://requestly.com/blog/modify-headers-in-https-requests-and-responses-in-chrome-firefox-safari/) [Exploit-notes](https://exploit-notes.hdks.org/exploit/web/tool/add-custom-http-headers-in-burp-suite/) [Website for testing header](https://httpbin.org/headers)*


## 1. Add Custom HTTP Headers in Burp Suite
