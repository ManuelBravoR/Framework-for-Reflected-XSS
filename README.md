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
>*Recursos: [Requestly](https://requestly.com/blog/modify-headers-in-https-requests-and-responses-in-chrome-firefox-safari/) [Exploit-notes](https://exploit-notes.hdks.org/exploit/web/tool/add-custom-http-headers-in-burp-suite/) [Website for testing header](https://httpbin.org/headers)*


## 2. Encontrar subdomains
```bash
subfinder -d testfire.net -silent -all -recursive -o testfire.net_subs.txt
amass enum -passive -d testfire.net -o testfire.net_amass_subs.txt
url -s "https://crt.sh/?q=%25.testfire.net&output=json" | jq -r '.[] | .name_value' | sed 's/\*\.//g' | anew testfire.net_crt.txt
github-subdomains -d testfire.net -t [github_toke] -o testfire.net_github_subs.txt
cat *_subs.txt | sort -u | anew testfire.net_all_subs.txt
```
```bash
# Obtener toekn github
#Fine-grained personal access tokens -> Generate new token
```
>*Recurso: [Generate Token](https://github.com/settings/personal-access-tokens/)

## 3. Web Crawling para encontrar URLs interesantes
```bash
#Simple command
katana -u testfire.net -silent -jc -o testfire.net_katana_results.txt
```
> Bash práctico para muchos subdomains
```bash
nano run_katana.sh
chmod +x run_katana.sh
./run_katana.sh
```
```bash
#!/bin/bash

INPUT="testfire.net_all_subs.txt"
OUTPUT="testfire.net_katana_results.txt"

# Limpiar salida anterior
> "$OUTPUT"

# Filtrar solo subdominios válidos y ejecutar katana
grep -oP '\b(?:[a-z0-9-]+\.)+testfire\.net\b' "$INPUT" | sort -u | while read -r sub; do
    echo "[+] Escaneando: http://$sub"
    katana -u "http://$sub" -silent -jc >> "$OUTPUT"
done

echo "[+] Finalizado. Resultados en $OUTPUT"
```

## 4. Buscar patrones comunes de XSS en URLs
```bash
nano filtrar_parameters_xss.sh
chmod +x filtrar_parameters_xss.sh
./filtrar_parameters_xss.sh
```
<details>
<summary>📜 Ver script Bash completo</summary>

```bash
#!/bin/bash

# Archivo de entrada
INPUT_FILE="testfire.net_katana_results.txt"

# Archivo de salida
OUTPUT_FILE="urls_patrones_xss.txt"

# Lista de parámetros sospechosos
PARAMS=(
"q"
"s"
"search"
"lang"
"keyword"
"query"
"page"
...
"begindate"
"enddate"
)

# Crear expresión regular separada por |
REGEX=$(IFS=\| ; echo "${PARAMS[*]}")

# Filtrar y guardar en archivo de salida
grep -Ei "\b(${REGEX})\b" "$INPUT_FILE" > "$OUTPUT_FILE"

echo "[+] Resultados guardados en $OUTPUT_FILE"
```
</details>


>*Recurso: [Patrones xss](https://github.com/1ndianl33t/Gf-Patterns/blob/master/xss.json)

## 5. Investigación de candidatos
```bash
#cat urls_patrones_xss.txt
https://demo.testfire.net/search.jsp
...
https://demo.testfire.net/swagger/err/error-transformers/transformers/not-of-type.js
https://demo.testfire.net/swagger/download-url.js
```

>*Recurso: [Payload xss comunes](https://github.com/payloadbox/xss-payload-list)


