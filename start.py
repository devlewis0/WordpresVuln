import requests

# Lista de URLs sensibles de WordPress
SENSITIVE_URLS = [
    '/wp-admin/',
    '/wp-login.php',
    '/wp-config.php',
    '/wp-content/plugins/',
    '/wp-content/themes/',
    '/wp-content/uploads/'
]

# Lista de plugins y temas vulnerables (ejemplo, normalmente obtendrías esta lista de una base de datos de vulnerabilidades)
VULNERABLE_PLUGINS = [
    'revslider',
    'contact-form-7',
    'wp-file-manager'
]

def check_sensitive_urls(base_url):
    print("Checking for sensitive URLs...")
    for url in SENSITIVE_URLS:
        full_url = base_url + url
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"[+] Accessible: {full_url}")
        else:
            print(f"[-] Not accessible: {full_url}")

def check_vulnerable_plugins(base_url):
    print("\nChecking for vulnerable plugins and themes...")
    for plugin in VULNERABLE_PLUGINS:
        full_url = f"{base_url}/wp-content/plugins/{plugin}/"
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"[+] Vulnerable plugin found: {plugin} at {full_url}")
        else:
            print(f"[-] Not found: {plugin}")

if __name__ == "__main__":
    base_url = input("Enter the WordPress site URL (e.g., http://example.com): ").strip()
    if not base_url.startswith('http'):
        base_url = 'http://' + base_url

    check_sensitive_urls(base_url)
    check_vulnerable_plugins(base_url)
    print("\nScan complete.")
