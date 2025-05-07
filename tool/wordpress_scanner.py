import requests
from colorama import Fore, Style
import re

def print_section(title):
    print(f"\n{Fore.BLUE}[==] {title}{Style.RESET_ALL}")

def detectar_wordpress(url, headers):
    print(f"\n[*] Verificando si el sitio utiliza WordPress...")
    rutas = ['wp-login.php', 'wp-admin/', 'wp-content/', 'wp-includes/']
    encontrado = False
    for ruta in rutas:
        try:
            res = requests.get(f"{url.rstrip('/')}/{ruta}", headers=headers, timeout=10)
            if res.status_code in [200, 403]:
                print(f"{Fore.GREEN}[+] Detectado indicio de WordPress en: /{ruta}{Style.RESET_ALL}")
                encontrado = True
        except:
            continue
    if not encontrado:
        print(f"{Fore.YELLOW}[!] No se detectaron rutas típicas de WordPress.{Style.RESET_ALL}")

def detectar_waf_cdn(url, headers):
    print(f"\n[*] Verificando presencia de CDN o WAF...")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        server = r.headers.get('Server', '').lower()
        waf_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        detectado = False

        if 'cloudflare' in server or 'cf-ray' in waf_headers:
            print(f"{Fore.CYAN}[+] Cloudflare detectado{Style.RESET_ALL}")
            detectado = True
        if 'akamai' in server or any('akamai' in k for k in waf_headers):
            print(f"{Fore.CYAN}[+] Akamai detectado{Style.RESET_ALL}")
            detectado = True
        if 'sucuri' in server or 'x-sucuri-id' in waf_headers:
            print(f"{Fore.CYAN}[+] Sucuri detectado{Style.RESET_ALL}")
            detectado = True
        if 'incapsula' in server or 'x-iinfo' in waf_headers:
            print(f"{Fore.CYAN}[+] Imperva/Incapsula detectado{Style.RESET_ALL}")
            detectado = True

        if not detectado:
            print(f"{Fore.YELLOW}[!] No se detectó WAF/CDN conocido en las cabeceras.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.MAGENTA}[x] Error al verificar WAF/CDN: {e}{Style.RESET_ALL}")

def verificar_wpconfig_bak(url, headers):
    print(f"\n[*] Intentando obtener contenido de wp-config.php.bak...")
    try:
        r = requests.get(f"{url.rstrip('/')}/wp-config.php.bak", headers=headers, timeout=10)
        if r.status_code == 200 and ('DB_NAME' in r.text or 'DB_USER' in r.text):
            print(f"{Fore.RED}[!!!] ¡Contenido sensible detectado en wp-config.php.bak!{Style.RESET_ALL}")
        elif r.status_code == 403:
            print(f"{Fore.YELLOW}[!] Acceso prohibido a wp-config.php.bak (403): Puede existir pero no accesible{Style.RESET_ALL}")
        elif r.status_code == 404:
            print(f"{Fore.YELLOW}[!] wp-config.php.bak no encontrado (404){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Código inesperado {r.status_code} al intentar acceder a wp-config.php.bak{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.MAGENTA}[x] Error al intentar acceder a wp-config.php.bak: {e}{Style.RESET_ALL}")

def escanear_vulnerabilidades(url, headers):
    print(f"\n[*] Verificando vulnerabilidades comunes en: {url}")
    rutas = {
        'wp-json/': "Divulgación de información vía REST API",
        'xmlrpc.php': "Interfaz XML-RPC (ataques bruteforce)",
        'wp-cron.php': "wp-cron expuesto (puede generar sobrecarga del servidor)",
        'readme.html': "readme.html encontrado (puede revelar la versión de WordPress)",
        'license.txt': "license.txt encontrado (puede revelar la versión de WordPress)",
        '.git/': "Directorio .git accesible (puede exponer código)",
        'wp-admin/install.php': "install.php accesible (puede indicar instalación incompleta o vulnerable)",
    }

    for ruta, descripcion in rutas.items():
        try:
            r = requests.get(f"{url.rstrip('/')}/{ruta}", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"{Fore.GREEN}[+] {ruta} accesible (200 OK): {descripcion}{Style.RESET_ALL}")
            elif r.status_code == 403:
                print(f"{Fore.YELLOW}[!] {ruta} existe pero está prohibido (403): {descripcion}{Style.RESET_ALL}")
            elif r.status_code == 405:
                print(f"{Fore.CYAN}[?] {ruta} devuelve código 405{Style.RESET_ALL}")
            elif r.status_code == 404:
                print(f"{Fore.YELLOW}[-] {ruta} no encontrado (404){Style.RESET_ALL}")
        except:
            continue

def verificar_pingback_xmlrpc(url, headers):
    print_section("Verificación de Pingback en xmlrpc.php")
    xmlrpc_url = f"{url.rstrip('/')}/xmlrpc.php"
    payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>http://example.com/</string></value>
    </param>
    <param>
      <value><string>{}</string></value>
    </param>
  </params>
</methodCall>""".format(url)

    try:
        r = requests.post(xmlrpc_url, data=payload, headers={**headers, "Content-Type": "application/xml"}, timeout=10)
        if "method not allowed" in r.text.lower() or "403" in r.text:
            print(f"{Fore.YELLOW}[!] El método pingback.ping está deshabilitado o el acceso está restringido.{Style.RESET_ALL}")
        elif "faultString" in r.text or r.status_code == 200:
            print(f"{Fore.CYAN}[+] El endpoint xmlrpc.php responde a pingback.ping — ¡potencialmente habilitado!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[?] No se pudo confirmar si pingback está habilitado. Respuesta ambigua.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.MAGENTA}[x] Error al verificar pingback: {e}{Style.RESET_ALL}")

def detectar_archivos_sensibles(url, headers):
    print(f"\n[*] Verificando archivos robots.txt y sitemap.xml...")
    archivos = ['robots.txt', 'sitemap.xml']
    for archivo in archivos:
        try:
            r = requests.get(f"{url.rstrip('/')}/{archivo}", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"{Fore.GREEN}[+] {archivo} accesible (200 OK): Puede contener rutas sensibles{Style.RESET_ALL}")
                if archivo == "robots.txt":
                    for linea in r.text.splitlines():
                        if "Disallow:" in linea or "Allow:" in linea:
                            print(f"    - Posible ruta sensible encontrada: {linea.strip()}")
            elif r.status_code == 403:
                print(f"{Fore.YELLOW}[!] {archivo} existe pero acceso prohibido (403){Style.RESET_ALL}")
            elif r.status_code == 404:
                print(f"{Fore.YELLOW}[-] {archivo} no encontrado (404){Style.RESET_ALL}")
        except:
            continue

def detectar_version(url, headers):
    print(f"\n[*] Intentando detectar la versión de WordPress...")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        version = re.search(r"content=\"WordPress (\d+\.\d+(\.\d+)?)", r.text)
        if version:
            print(f"{Fore.GREEN}[+] Versión detectada: WordPress {version.group(1)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No se pudo detectar la versión de WordPress en el HTML.{Style.RESET_ALL}")
    except:
        print(f"{Fore.MAGENTA}[x] Error al intentar detectar la versión de WordPress.{Style.RESET_ALL}")

def enumerar_usuarios(url, headers):
    print(f"\n[*] Buscando usuarios a través del endpoint REST API...")
    try:
        r = requests.get(f"{url.rstrip('/')}/wp-json/wp/v2/users", headers=headers, timeout=10)
        if r.status_code == 200 and "slug" in r.text:
            datos = r.json()
            print(f"{Fore.GREEN}[+] Usuarios encontrados:{Style.RESET_ALL}")
            for user in datos:
                print(f"    - ID: {user.get('id')} | Nombre: {user.get('name')} | Slug: {user.get('slug')}")
        else:
            print(f"{Fore.YELLOW}[!] No se pudieron enumerar usuarios o el endpoint no está accesible.{Style.RESET_ALL}")
    except:
        print(f"{Fore.MAGENTA}[x] Error al intentar enumerar usuarios.{Style.RESET_ALL}")

def escanear_plugins(url, headers):
    print(f"\n[*] Escaneando plugins comunes...")
    plugins = ['akismet', 'contact-form-7', 'wordfence', 'woocommerce', 'jetpack']
    for plugin in plugins:
        try:
            r = requests.get(f"{url.rstrip('/')}/wp-content/plugins/{plugin}/", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"{Fore.GREEN}[+] Plugin encontrado: {plugin}{Style.RESET_ALL}")
        except:
            continue

def escanear_temas(url, headers):
    print(f"\n[*] Escaneando temas comunes...")
    temas = ['astra', 'twentytwentyfour', 'twentytwentythree', 'hello-elementor']
    for tema in temas:
        try:
            r = requests.get(f"{url.rstrip('/')}/wp-content/themes/{tema}/", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"{Fore.GREEN}[+] Tema encontrado: {tema}{Style.RESET_ALL}")
        except:
            continue

if __name__ == "__main__":
    target_url = input("Introduce la URL del sitio WordPress (ej. https://dominio.com/ o www.dominio.com): ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; WPScanner/1.0)'}

    detectar_wordpress(target_url, headers)
    detectar_waf_cdn(target_url, headers)
    verificar_wpconfig_bak(target_url, headers)
    escanear_vulnerabilidades(target_url, headers)
    detectar_archivos_sensibles(target_url, headers)
    detectar_version(target_url, headers)
    enumerar_usuarios(target_url, headers)
    escanear_plugins(target_url, headers)
    escanear_temas(target_url, headers)
    verificar_pingback_xmlrpc(target_url, headers)