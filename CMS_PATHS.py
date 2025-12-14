#!/usr/bin/env python3
import requests
import csv
import os
import time
from urllib.parse import urljoin
import sys

# =======================
# CONFIGURACIÓN
# =======================
TIMEOUT = 8
HEADERS = {"User-Agent": "Advanced-Security-Audit/2.0"}
DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# =======================
# COLORES
# =======================
GREEN = "\033[92m"  # 200
ORANGE = "\033[93m"  # 301 / 302
RED = "\033[91m"  # 4XX
BLUE = "\033[94m"
CYAN = "\033[96m"  # 403
PURPLE = "\033[95m"  # Para detección CMS
RESET = "\033[0m"

# =======================
# ESTADOS HTTP
# =======================
STATUS_DESC = {
    200: "🔥 CRÍTICO – acceso directo",
    301: "↪ Redirección permanente",
    302: "↪ Redirección temporal",
    401: "⚠️ Autenticación requerida",
    403: "⚠️ Existe, pero protegido",
    404: "OK / no existe",
    500: "💥 Error interno del servidor"
}

# =======================
# BASE DE DATOS DE CVEs
# =======================
CVE_DATABASE = {
    "Drupal": {
        200: ["CVE-2018-7600", "CVE-2019-6340", "CVE-2020-13671"],
        403: ["CVE-2018-7602", "CVE-2019-6341"],
        "install": ["CVE-2014-3704", "CVE-2017-6920"],
        "config": ["Múltiples CVEs por exposición de archivos de configuración"],
        "settings": ["CVE-2018-7600", "CVE-2019-6340"],
        "default": ["Múltiples CVEs por exposición de archivos de configuración"]
    },
    "WordPress": {
        200: ["CVE-2021-44223", "CVE-2022-21661", "CVE-2022-21664"],
        403: ["CVE-2021-44228", "CVE-2022-22965"],
        "config": ["CVE-2017-8295", "CVE-2018-12895"],
        "wp-admin": ["CVE-2022-21662", "CVE-2021-44223"],
        "default": ["Múltiples CVEs por archivos de configuración expuestos"]
    },
    "Joomla": {
        200: ["CVE-2023-23752", "CVE-2022-23731", "CVE-2021-23132"],
        403: ["CVE-2020-35616", "CVE-2019-19833"],
        "config": ["CVE-2015-8562", "CVE-2016-8870"],
        "administrator": ["CVE-2023-23752", "CVE-2022-23731"],
        "default": ["Múltiples CVEs por configuración expuesta"]
    },
    "Laravel": {
        200: ["CVE-2021-3129", "CVE-2018-15133", "CVE-2022-30778"],
        "env": ["CVE-2017-16894", "CVE-2018-15133"],
        "config": ["CVE-2021-3129", "CVE-2018-15133"],
        "default": ["Exposición de variables de entorno sensibles"]
    },
    "Magento": {
        200: ["CVE-2022-24086", "CVE-2021-40858", "CVE-2020-24400"],
        403: ["CVE-2019-8144", "CVE-2018-17083"],
        "config": ["CVE-2019-8144", "CVE-2018-17083"],
        "admin": ["CVE-2022-24086", "CVE-2021-40858"],
        "default": ["Múltiples CVEs en Magento"]
    },
    "PrestaShop": {
        200: ["CVE-2023-30846", "CVE-2022-36408", "CVE-2021-32648"],
        403: ["CVE-2020-8644", "CVE-2019-13568"],
        "default": ["Múltiples CVEs en PrestaShop"]
    },
    "OpenCart": {
        200: ["CVE-2023-47444", "CVE-2021-32647", "CVE-2020-29473"],
        403: ["CVE-2019-19622", "CVE-2018-19412"],
        "default": ["Múltiples CVEs en OpenCart"]
    },
    "Moodle": {
        200: ["CVE-2023-30943", "CVE-2022-35092", "CVE-2021-43560"],
        403: ["CVE-2020-14322", "CVE-2019-14865"],
        "default": ["Múltiples CVEs en Moodle"]
    },
    "TYPO3": {
        200: ["CVE-2023-48716", "CVE-2022-23457", "CVE-2021-21360"],
        403: ["CVE-2020-11077", "CVE-2019-12744"],
        "default": ["Múltiples CVEs en TYPO3"]
    },
    "Ghost": {
        200: ["CVE-2023-32235", "CVE-2022-41654", "CVE-2021-43798"],
        403: ["CVE-2020-24341", "CVE-2019-19638"],
        "default": ["Múltiples CVEs en Ghost"]
    },
    "Generic": {
        200: ["CVE variados por exposición de archivos sensibles"],
        403: ["Posibles vectores de ataque de fuerza bruta"],
        "config": ["CVE-2017-15715", "CVE-2018-13379"],
        "default": ["Vulnerabilidades genéricas de exposición de archivos"]
    }
}

# =======================
# RECOMENDACIONES DE SEGURIDAD
# =======================
RECOMMENDATIONS = {
    200: "Mover el archivo fuera del directorio público y restringir permisos. Implementar reglas de acceso en el servidor web.",
    301: "Validar que las redirecciones sean legítimas y no conduzcan a sitios maliciosos.",
    302: "Verificar que las redirecciones temporales sean apropiadas y seguras.",
    403: "Aplicar controles de acceso y hardening del servidor web. Revisar configuraciones de permisos.",
    404: "Estado correcto para archivos que no deberían ser accesibles públicamente.",
    401: "Implementar autenticación fuerte y monitorear intentos de acceso no autorizados.",
    500: "Revisar logs del servidor para identificar errores de configuración o explotación.",
    
    # Recomendaciones específicas por tipo de archivo
    "install": "Eliminar scripts de instalación tras el despliegue. Restringir acceso a directorios de instalación.",
    "config": "Proteger archivos de configuración con .htaccess o configuraciones equivalentes del servidor. No almacenar en directorio web.",
    "env": "Proteger archivos .env y utilizar variables de entorno del sistema. No versionar en repositorios.",
    "log": "Restringir acceso a archivos de log y moverlos fuera del directorio web root. Implementar rotación de logs.",
    "backup": "Eliminar archivos de backup del entorno de producción o moverlos a ubicaciones seguras. No almacenar en directorio web.",
    "admin": "Implementar autenticación de dos factores para paneles administrativos. Restringir por IP si es posible.",
    "database": "No almacenar archivos de base de datos en directorios web. Usar conexiones seguras y credenciales fuertes.",
    "git": "Evitar que directorios .git sean accesibles públicamente. Configurar .gitignore apropiadamente.",
    "default": "Implementar principios de mínimo privilegio y revisar configuraciones de seguridad regularmente."
}

# =======================
# PATRONES DE DETECCIÓN DE CMS
# =======================
CMS_PATTERNS = {
    "WordPress": [
        ("wp-content", "text"),
        ("wp-includes", "text"),
        ("wordpress", "text"),
        ("/wp-json/", "url"),
        ("/xmlrpc.php", "url")
    ],
    "Drupal": [
        ("drupal", "text"),
        ("sites/all/", "text"),
        ("sites/default/", "text"),
        ("/core/misc/drupal.js", "url")
    ],
    "Joomla": [
        ("joomla", "text"),
        ("/media/system/js/", "text"),
        ("/media/jui/js/", "text"),
        ("/administrator/", "url")
    ],
    "Laravel": [
        ("laravel", "text"),
        ("csrf-token", "text"),
        ("/storage/", "url")
    ],
    "Magento": [
        ("magento", "text"),
        ("/static/version", "text"),
        ("/media/", "url"),
        ("/skin/", "url")
    ],
    "PrestaShop": [
        ("prestashop", "text"),
        ("/js/tools.js", "url"),
        ("/themes/", "url")
    ],
    "OpenCart": [
        ("opencart", "text"),
        ("/catalog/", "url"),
        ("/system/", "url")
    ],
    "Moodle": [
        ("moodle", "text"),
        ("/theme/styles.php", "url"),
        ("/lib/javascript.php", "url")
    ],
    "TYPO3": [
        ("typo3", "text"),
        ("/typo3conf/", "url"),
        ("/typo3temp/", "url")
    ],
    "Ghost": [
        ("ghost", "text"),
        ("/ghost/", "url"),
        ("/content/images/", "url")
    ]
}

# =======================
# CMS + RUTAS (ORIGINAL + NUEVAS RUTAS)
# =======================
CMS_PATHS = {
    "Drupal": [
        "/sites/default/settings.php",
        "/sites/default/settings.local.php",
        "/sites/default/services.yml",
        "/sites/default/default.settings.php",
        "/sites/default/files/php.ini",
        "/sites/default/files/.htaccess",
        "/core/install.php",
        "/install.php",
        "/update.php",
        "/CHANGELOG.txt",
        "/README.txt",
        "/sites/default/private/settings.php",
        "/sites/default/private/files/.htaccess",
        "/sites/default/files/.htpasswd",
        "/sites/default/files/backup.sql",
        "/sites/default/files/database.sql",
        "/sites/all/modules/contrib/",
        "/sites/all/themes/",
        "/admin/config/development/configuration",
        "/admin/reports/status",
        "/cron.php",
        "/user/password",
        "/user/register",
        "/sites/default/files/config/sync/core.extension.yml",
        "/sites/default/files/php/php.ini",
        "/sites/default/files/logs/drupal.log",
        "/sites/default/files/error.log",
        "/web.config",
        "/robots.txt",
        "/.git/config",
        "/.env.drupal",
        "/scripts/drupal.sh"
    ],
    
    "WordPress": [
        "/wp-config.php",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.php.save",
        "/wp-config-sample.php",
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/debug.log",
        "/wp-content/uploads/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/xmlrpc.php",
        "/readme.html",
        "/license.txt",
        "/changelog.txt",
        "/robots.txt",
        "/wp-content/uploads/wp-config.php",
        "/wp-content/backup-db/",
        "/wp-content/backups/",
        "/wp-content/backup/",
        "/wp-content/cache/",
        "/wp-content/upgrade/",
        "/wp-admin/admin-ajax.php",
        "/wp-admin/install.php",
        "/wp-admin/setup-config.php",
        "/wp-admin/upgrade.php",
        "/wp-includes/version.php",
        "/.user.ini",
        "/wp-config.php.backup",
        "/wp-config.php.dist",
        "/wp-config.php.orig",
        "/wp-config.php.original",
        "/wp-config.php.temp",
        "/wp-config.php.tmp",
        "/wp-config.php~",
        "/wp-config.bak",
        "/wp-config.old",
        "/wp-config.save",
        "/wp-config-sample.php.bak",
        "/wp-config-sample.php.old",
        "/wp-admin/error_log",
        "/wp-content/error_log",
        "/error_log",
        "/.htaccess.bak",
        "/.htaccess.old",
        "/backup.zip",
        "/database.sql",
        "/wp-content/plugins/hello.php",
        "/wp-content/themes/twenty*/style.css"
    ],
    
    "Joomla": [
        "/configuration.php",
        "/administrator/",
        "/installation/",
        "/logs/",
        "/tmp/",
        "/configuration.php.bak",
        "/configuration.php.old",
        "/configuration.php.save",
        "/configuration.php.dist",
        "/configuration.php.orig",
        "/configuration.php.original",
        "/configuration.php~",
        "/configuration.php.backup",
        "/administrator/configuration.php",
        "/administrator/logs/",
        "/administrator/backup/",
        "/administrator/error_log",
        "/logs/error.php",
        "/logs/error.log",
        "/error_log",
        "/tmp/error.log",
        "/cache/error.log",
        "/images/error.log",
        "/media/error.log",
        "/components/com_users/",
        "/plugins/system/",
        "/templates/",
        "/.htaccess.bak",
        "/.htaccess.old",
        "/web.config.txt",
        "/htaccess.txt",
        "/joomla.xml",
        "/LICENSE.txt",
        "/README.txt",
        "/CHANGELOG"
    ],
    
    "Laravel": [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/storage/logs/laravel.log",
        "/config/database.php",
        "/artisan",
        "/.env.example",
        "/.env.testing",
        "/.env.development",
        "/.env.staging",
        "/.env.production.local",
        "/.env.dev",
        "/.env.prod",
        "/.env.backup",
        "/.env.old",
        "/.env.save",
        "/.env.dist",
        "/.env.orig",
        "/config/app.php",
        "/config/auth.php",
        "/config/services.php",
        "/config/mail.php",
        "/storage/framework/",
        "/storage/logs/",
        "/storage/app/",
        "/database/seeders/",
        "/database/migrations/",
        "/database/database.sqlite",
        "/database.sqlite",
        "/routes/console.php",
        "/public/index.php",
        "/server.php",
        "/bootstrap/cache/",
        "/vendor/",
        "/composer.json",
        "/composer.lock",
        "/phpunit.xml",
        "/yarn.lock",
        "/package.json"
    ],
    
    "Magento": [
        "/app/etc/env.php",
        "/app/etc/config.php",
        "/var/log/",
        "/setup/",
        "/app/etc/env.php.bak",
        "/app/etc/env.php.old",
        "/app/etc/env.php.save",
        "/app/etc/config.php.bak",
        "/app/etc/config.php.old",
        "/app/etc/config.php.save",
        "/app/etc/local.xml",
        "/app/etc/local.xml.bak",
        "/app/etc/local.xml.old",
        "/var/backups/",
        "/var/export/",
        "/var/import/",
        "/var/importexport/",
        "/var/log/exception.log",
        "/var/log/system.log",
        "/var/log/debug.log",
        "/var/report/",
        "/pub/errors/",
        "/pub/media/",
        "/pub/static/",
        "/index.php/install",
        "/install.php",
        "/.htaccess.sample",
        "/.htaccess.bak",
        "/.user.ini",
        "/php.ini.sample",
        "/composer.json",
        "/composer.lock",
        "/Gruntfile.js",
        "/package.json",
        "/yarn.lock"
    ],
    
    "Generic": [
        "/config.php",
        "/database.php",
        "/credentials.php",
        "/settings.ini",
        "/config.yml",
        "/config.json",
        "/admin",
        "/login",
        "/backup.zip",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/site-backup.zip",
        "/.git/",
        "/.gitignore",
        "/.env",
        "/.htpasswd",
        "/phpinfo.php",
        "/config/config.php",
        "/config/database.php",
        "/config/credentials.php",
        "/config/settings.php",
        "/application/config/config.php",
        "/application/config/database.php",
        "/application/config/settings.php",
        "/app/config/config.php",
        "/app/config/database.php",
        "/app/config/settings.php",
        "/system/config/config.php",
        "/system/config/database.php",
        "/includes/config.php",
        "/includes/database.php",
        "/inc/config.php",
        "/inc/database.php",
        "/src/config.php",
        "/src/database.php",
        "/web/config.php",
        "/web/database.php",
        "/config.php.dist",
        "/config.php.example",
        "/config.php.sample",
        "/config.php.default",
        "/config.php.orig",
        "/config.php.original",
        "/config.php.backup",
        "/config.php.bak",
        "/config.php.old",
        "/config.php.save",
        "/config.php.tmp",
        "/config.php.temp",
        "/config.php~",
        "/database.php.dist",
        "/database.php.example",
        "/database.php.sample",
        "/database.php.default",
        "/database.php.orig",
        "/database.php.original",
        "/database.php.backup",
        "/database.php.bak",
        "/database.php.old",
        "/database.php.save",
        "/.env.example",
        "/.env.sample",
        "/.env.dist",
        "/.env.default",
        "/.env.test",
        "/.env.testing",
        "/.env.development",
        "/.env.staging",
        "/.env.production",
        "/.env.local",
        "/.env.prod",
        "/.env.dev",
        "/.env.backup",
        "/.env.bak",
        "/.env.old",
        "/.env.save",
        "/admin/",
        "/admin123/",
        "/admin456/",
        "/administrator/",
        "/administrador/",
        "/manager/",
        "/manage/",
        "/management/",
        "/panel/",
        "/paneladmin/",
        "/adminpanel/",
        "/cp/",
        "/controlpanel/",
        "/backend/",
        "/backoffice/",
        "/sysadmin/",
        "/superadmin/",
        "/root/",
        "/moderator/",
        "/operator/",
        "/user/",
        "/users/",
        "/member/",
        "/members/",
        "/account/",
        "/accounts/",
        "/dashboard/",
        "/dash/",
        "/console/",
        "/webadmin/",
        "/siteadmin/",
        "/login.php",
        "/login.html",
        "/log-in.php",
        "/log-in.html",
        "/signin.php",
        "/signin.html",
        "/sign-in.php",
        "/sign-in.html",
        "/auth.php",
        "/auth.html",
        "/authentication.php",
        "/authenticate.php",
        "/signup.php",
        "/signup.html",
        "/register.php",
        "/register.html",
        "/registration.php",
        "/account.php",
        "/account.html",
        "/user.php",
        "/user.html",
        "/member.php",
        "/member.html",
        "/backup/",
        "/backups/",
        "/backup_files/",
        "/backupfiles/",
        "/backup_data/",
        "/backupdata/",
        "/database_backup/",
        "/db_backup/",
        "/sql_backup/",
        "/site_backup/",
        "/web_backup/",
        "/full_backup/",
        "/backup.tar",
        "/backup.tar.gz",
        "/backup.tgz",
        "/backup.rar",
        "/backup.7z",
        "/backup.gz",
        "/backup.bz2",
        "/dump.sql",
        "/dump.sql.gz",
        "/dump.sql.bz2",
        "/data.sql",
        "/data.sql.gz",
        "/data.sql.bz2",
        "/export.sql",
        "/export.sql.gz",
        "/export.sql.bz2",
        "/import.sql",
        "/import.sql.gz",
        "/import.sql.bz2",
        "/logs/",
        "/log/",
        "/logging/",
        "/debug/",
        "/debug_log/",
        "/error/",
        "/errors/",
        "/error.log",
        "/error_log",
        "/errors.log",
        "/debug.log",
        "/debug_log.txt",
        "/php_errors.log",
        "/php_error.log",
        "/php_errors",
        "/php_error",
        "/app.log",
        "/application.log",
        "/system.log",
        "/site.log",
        "/web.log",
        "/access.log",
        "/access_log",
        "/php.ini",
        "/php.ini.bak",
        "/php.ini.old",
        "/php.ini.save",
        "/php.ini.dist",
        "/php.ini.example",
        "/.htaccess",
        "/.htaccess.bak",
        "/.htaccess.old",
        "/.htaccess.save",
        "/.htaccess.dist",
        "/.htaccess.example",
        "/htaccess.txt",
        "/htaccess.html",
        "/web.config",
        "/web.config.bak",
        "/web.config.old",
        "/web.config.save",
        "/web.config.dist",
        "/web.config.example",
        "/httpd.conf",
        "/httpd.conf.bak",
        "/httpd.conf.old",
        "/nginx.conf",
        "/nginx.conf.bak",
        "/nginx.conf.old",
        "/info.php",
        "/phpinfo.php",
        "/test.php",
        "/test.html",
        "/test.txt",
        "/check.php",
        "/status.php",
        "/server-status",
        "/server-info",
        "/README",
        "/README.md",
        "/README.txt",
        "/README.html",
        "/README.pdf",
        "/CHANGELOG",
        "/CHANGELOG.md",
        "/CHANGELOG.txt",
        "/CHANGELOG.html",
        "/LICENSE",
        "/LICENSE.md",
        "/LICENSE.txt",
        "/LICENSE.html",
        "/COPYING",
        "/COPYING.txt",
        "/install/",
        "/installation/",
        "/setup/",
        "/set-up/",
        "/initialize/",
        "/init/",
        "/install.php",
        "/install.html",
        "/install.sh",
        "/install.bat",
        "/setup.php",
        "/setup.html",
        "/setup.sh",
        "/setup.bat",
        "/upgrade.php",
        "/upgrade.html",
        "/update.php",
        "/update.html",
        "/migrate.php",
        "/migrate.html",
        "/test/",
        "/testing/",
        "/demo/",
        "/demonstration/",
        "/example/",
        "/examples/",
        "/sample/",
        "/samples/",
        "/test.php",
        "/test.html",
        "/test.txt",
        "/demo.php",
        "/demo.html",
        "/demo.txt",
        "/example.php",
        "/example.html",
        "/example.txt",
        "/sample.php",
        "/sample.html",
        "/sample.txt",
        "/cache/",
        "/caches/",
        "/caching/",
        "/temp/",
        "/tmp/",
        "/temporary/",
        "/temporarily/",
        "/temporaries/",
        "/uploads/",
        "/upload/",
        "/uploaded/",
        "/uploading/",
        "/media/",
        "/medias/",
        "/files/",
        "/file/",
        "/images/",
        "/image/",
        "/pictures/",
        "/picture/",
        "/photos/",
        "/photo/",
        "/videos/",
        "/video/",
        "/audios/",
        "/audio/",
        "/documents/",
        "/document/",
        "/attachments/",
        "/attachment/",
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/composer.json",
        "/composer.lock",
        "/pom.xml",
        "/build.xml",
        "/Gruntfile.js",
        "/gulpfile.js",
        "/webpack.config.js",
        "/bower.json",
        "/requirements.txt",
        "/Pipfile",
        "/Pipfile.lock",
        "/Gemfile",
        "/Gemfile.lock",
        "/go.mod",
        "/go.sum",
        "/Cargo.toml",
        "/Cargo.lock",
        "/.idea/",
        "/.vscode/",
        "/.vs/",
        "/.project",
        "/.classpath",
        "/.settings/",
        "/.metadata/",
        "/.buildpath",
        "/.git/HEAD",
        "/.git/config",
        "/.git/description",
        "/.gitignore",
        "/.gitattributes",
        "/.svn/",
        "/.hg/",
        "/.bzr/",
        "/.bashrc",
        "/.bash_profile",
        "/.profile",
        "/.ssh/",
        "/.ssh/config",
        "/.ssh/authorized_keys",
        "/.ssh/id_rsa",
        "/.ssh/id_rsa.pub",
        "/.ssh/id_dsa",
        "/.ssh/id_dsa.pub",
        "/.ssh/known_hosts",
        "/db/",
        "/database/",
        "/databases/",
        "/data/",
        "/datas/",
        "/database.db",
        "/database.sqlite",
        "/database.sqlite3",
        "/data.db",
        "/data.sqlite",
        "/data.sqlite3",
        "/app.db",
        "/app.sqlite",
        "/app.sqlite3",
        "/site.db",
        "/site.sqlite",
        "/site.sqlite3",
        "/web.db",
        "/web.sqlite",
        "/web.sqlite3",
        "/sessions/",
        "/session/",
        "/sess_",
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/api/v3/",
        "/rest/",
        "/rest/api/",
        "/graphql",
        "/graphql/",
        "/soap/",
        "/xmlrpc/",
        "/jsonrpc/",
        "/ws/",
        "/webservice/",
        "/webservices/",
        "/web-service/",
        "/web-services/",
        "/wsdl",
        "/wsdl/",
        "/WSDL",
        "/WSDL/",
        "/service.wsdl",
        "/services.wsdl",
        "/api.wsdl",
        "/soap.wsdl",
        "/doc/",
        "/docs/",
        "/documentation/",
        "/documentations/",
        "/help/",
        "/helps/",
        "/guide/",
        "/guides/",
        "/manual/",
        "/manuals/",
        "/configuration.php",
        "/configuration.php.bak",
        "/configuration.php.old",
        "/configuration.php.save",
        "/configuration.php.dist",
        "/settings.php",
        "/settings.php.bak",
        "/settings.php.old",
        "/settings.php.save",
        "/settings.php.dist",
        "/parameters.php",
        "/parameters.php.bak",
        "/parameters.php.old",
        "/parameters.php.save",
        "/parameters.php.dist",
        "/parameters.yml",
        "/parameters.yml.bak",
        "/parameters.yml.old",
        "/parameters.yml.save",
        "/parameters.yml.dist",
        "/parameters.yaml",
        "/parameters.yaml.bak",
        "/parameters.yaml.old",
        "/parameters.yaml.save",
        "/parameters.yaml.dist",
        "/.env.local",
        "/.env.local.php",
        "/.env.local.yml",
        "/.env.local.yaml",
        "/.env.production",
        "/.env.production.php",
        "/.env.production.yml",
        "/.env.production.yaml",
        "/.env.development",
        "/.env.development.php",
        "/.env.development.yml",
        "/.env.development.yaml",
        "/.env.staging",
        "/.env.staging.php",
        "/.env.staging.yml",
        "/.env.staging.yaml",
        "/.env.test",
        "/.env.test.php",
        "/.env.test.yml",
        "/.env.test.yaml",
        "/robots.txt",
        "/robots.php",
        "/robots.html",
        "/sitemap.xml",
        "/sitemap.php",
        "/sitemap.html",
        "/sitemap.txt",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/favicon.ico",
        "/feed/",
        "/rss/",
        "/rss.xml",
        "/atom.xml",
        "/feed.xml",
        "/rss.php",
        "/atom.php",
        "/feed.php",
        "/themes/",
        "/theme/",
        "/templates/",
        "/template/",
        "/layouts/",
        "/layout/",
        "/skins/",
        "/skin/",
        "/styles/",
        "/style/",
        "/css/",
        "/stylesheets/",
        "/stylesheet/",
        "/scripts/",
        "/script/",
        "/js/",
        "/javascript/",
        "/javascripts/",
        "/javascript/",
        "/styles/",
        "/style/",
        "/css/",
        "/stylesheets/",
        "/stylesheet/",
        "/fonts/",
        "/font/",
        "/lib/",
        "/libs/",
        "/library/",
        "/libraries/",
        "/vendor/",
        "/vendors/",
        "/modules/",
        "/module/",
        "/plugins/",
        "/plugin/",
        "/extensions/",
        "/extension/",
        "/addons/",
        "/addon/",
        "/.well-known/",
        "/.well-known/acme-challenge/",
        "/.well-known/pki-validation/",
        "/ssl/",
        "/cert/",
        "/certs/",
        "/certificate/",
        "/certificates/",
        "/.crt",
        "/.pem",
        "/.key",
        "/.bash_history",
        "/.history",
        "/.sh_history",
        "/core",
        "/core.*",
        "/dump.*",
        "/memory.dmp",
        "/Dockerfile",
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/dockerfile",
        "/docker-compose",
        "/kubeconfig",
        "/.kube/config",
        "/.aws/credentials",
        "/.aws/config",
        "/.azure/credentials",
        "/.gcloud/credentials",
        "/health",
        "/healthz",
        "/healthcheck",
        "/status",
        "/ready",
        "/live",
        "/ping",
        "/heartbeat",
        "/metrics",
        "/prometheus",
        "/grafana/",
        "/monitoring/",
        "/phpmyadmin/",
        "/adminer/",
        "/mysql/",
        "/mysql-admin/",
        "/pma/",
        "/myadmin/",
        "/dbadmin/",
        "/database-admin/",
        "/sql/",
        "/sqladmin/",
        "/webmysql/",
        "/websql/",
        "/wordlist.txt",
        "/password.txt",
        "/passwords.txt",
        "/users.txt",
        "/usernames.txt",
        "/emails.txt"
    ]
}

# =======================
# DETECCIÓN AVANZADA DE CMS
# =======================
def detect_cms(base):
    detected_cms = []
    
    print(f"{BLUE}[*]{RESET} Iniciando detección de CMS...")
    
    # Primero intentar con la página principal
    try:
        r = requests.get(base, headers=HEADERS, timeout=TIMEOUT)
        content = r.text.lower()
        
        # Verificar patrones en el HTML
        for cms, patterns in CMS_PATTERNS.items():
            for pattern, pattern_type in patterns:
                if pattern_type == "text" and pattern.lower() in content:
                    detected_cms.append(cms)
                    print(f"{PURPLE}[+]{RESET} Posible {cms} detectado por patrón: {pattern}")
                    break
                elif pattern_type == "url":
                    # Probar la URL específica
                    test_url = urljoin(base, pattern)
                    try:
                        r_test = requests.get(test_url, headers=HEADERS, timeout=2)
                        if r_test.status_code < 400:
                            detected_cms.append(cms)
                            print(f"{PURPLE}[+]{RESET} Posible {cms} detectado por URL: {pattern}")
                            break
                    except:
                        pass
        
        # Verificar headers específicos
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        if 'x-powered-by' in headers_lower:
            powered_by = headers_lower['x-powered-by']
            for cms in CMS_PATTERNS.keys():
                if cms.lower() in powered_by:
                    detected_cms.append(cms)
                    print(f"{PURPLE}[+]{RESET} {cms} detectado en header X-Powered-By")
    
    except Exception as e:
        print(f"{RED}[!]{RESET} Error al analizar página principal: {e}")
    
    # Probar URLs específicas de CMS
    test_urls = [
        ("/wp-admin/", "WordPress"),
        ("/administrator/", "Joomla"),
        ("/admin/", "Drupal"),
        ("/typo3/", "TYPO3"),
        ("/ghost/", "Ghost"),
        ("/xmlrpc.php", "WordPress"),
        ("/wp-json/", "WordPress"),
    ]
    
    for path, cms in test_urls:
        test_url = urljoin(base, path)
        try:
            r_test = requests.get(test_url, headers=HEADERS, timeout=2)
            if r_test.status_code < 400:
                detected_cms.append(cms)
                print(f"{PURPLE}[+]{RESET} Posible {cms} detectado por acceso a: {path}")
        except:
            pass
    
    # Eliminar duplicados y determinar el CMS principal
    detected_cms = list(set(detected_cms))
    
    if detected_cms:
        # Priorizar CMS específicos sobre "Generic"
        cms_priority = ["WordPress", "Drupal", "Joomla", "Magento", "Laravel", 
                       "PrestaShop", "OpenCart", "Moodle", "TYPO3", "Ghost"]
        
        for cms in cms_priority:
            if cms in detected_cms:
                print(f"{GREEN}[✓]{RESET} CMS detectado: {cms}")
                return cms
    
    print(f"{ORANGE}[!]{RESET} No se pudo detectar CMS específico, usando rutas genéricas")
    return "Generic"

# =======================
# OBTENER CVEs BASADO EN RUTA Y ESTADO
# =======================
def get_cves_for_path(cms, status, path):
    """Obtiene CVEs relevantes basados en CMS, estado HTTP y ruta"""
    
    # CVEs basados en estado HTTP
    cves = CVE_DATABASE.get(cms, {}).get(status, [])
    
    # CVEs basados en patrones de ruta
    if "install" in path or "setup" in path:
        cves.extend(CVE_DATABASE.get(cms, {}).get("install", []))
    
    if "config" in path or "settings" in path or "env" in path:
        cves.extend(CVE_DATABASE.get(cms, {}).get("config", []))
    
    if "admin" in path or "administrator" in path or "wp-admin" in path:
        cves.extend(CVE_DATABASE.get(cms, {}).get("admin", []))
    
    if "wp-config" in path:
        cves.extend(CVE_DATABASE.get(cms, {}).get("config", []))
    
    if ".env" in path:
        cves.extend(CVE_DATABASE.get(cms, {}).get("env", []))
    
    # Eliminar duplicados
    cves = list(set(cves))
    
    # Si no hay CVEs específicos, usar los default
    if not cves:
        cves = CVE_DATABASE.get(cms, {}).get("default", ["CVE no específico identificado"])
    
    return ", ".join(cves[:3])  # Máximo 3 CVEs

# =======================
# OBTENER RECOMENDACIÓN
# =======================
def get_recommendation(status, path):
    """Obtiene recomendación basada en estado HTTP y tipo de ruta"""
    
    # Recomendación basada en estado HTTP
    recommendation = RECOMMENDATIONS.get(status, RECOMMENDATIONS["default"])
    
    # Recomendaciones específicas por tipo de archivo
    if "install" in path or "setup" in path:
        recommendation = RECOMMENDATIONS.get("install", recommendation)
    
    if "config" in path or "settings" in path or "wp-config" in path or "configuration" in path:
        recommendation = RECOMMENDATIONS.get("config", recommendation)
    
    if ".env" in path:
        recommendation = RECOMMENDATIONS.get("env", recommendation)
    
    if "log" in path or "debug" in path or "error" in path:
        recommendation = RECOMMENDATIONS.get("log", recommendation)
    
    if "backup" in path or "dump" in path or ".sql" in path or ".zip" in path:
        recommendation = RECOMMENDATIONS.get("backup", recommendation)
    
    if "admin" in path or "administrator" in path or "wp-admin" in path:
        recommendation = RECOMMENDATIONS.get("admin", recommendation)
    
    if ".git" in path:
        recommendation = RECOMMENDATIONS.get("git", recommendation)
    
    if ".sql" in path or ".db" in path:
        recommendation = RECOMMENDATIONS.get("database", recommendation)
    
    return recommendation

# =======================
# DESCARGA SEGURA
# =======================
def safe_download(url, cms):
    try:
        name = url.split("/")[-1] or "index"
        if "?" in name:
            name = name.split("?")[0]
        
        # Limpiar nombre de archivo
        safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
        if not safe_name:
            safe_name = "file"
        
        path = os.path.join(DOWNLOAD_DIR, f"{cms}_{safe_name}")
        
        # Evitar descargar archivos muy grandes
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True)
        if r.status_code == 200:
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > 10_000_000:  # 10MB límite
                print(f"{ORANGE}[!]{RESET} Archivo demasiado grande para descargar: {url}")
                return
            
            with open(path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            file_size = os.path.getsize(path)
            print(f"{GREEN}[↓]{RESET} Descargado: {safe_name} ({file_size} bytes)")
    except Exception as e:
        pass

# =======================
# ESCANEO DE RUTAS
# =======================
def scan_paths(target, cms):
    results = []
    
    if cms not in CMS_PATHS:
        print(f"{RED}[!]{RESET} No hay rutas definidas para {cms}, usando Generic")
        cms = "Generic"
    
    paths = CMS_PATHS.get(cms, [])
    total_paths = len(paths)
    
    print(f"{BLUE}[*]{RESET} Escaneando {total_paths} rutas para {cms}...")
    
    for i, path in enumerate(paths, 1):
        url = urljoin(target, path)
        
        # Mostrar progreso
        if i % 10 == 0 or i == total_paths:
            print(f"{BLUE}[*]{RESET} Progreso: {i}/{total_paths}", end='\r')
        
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            status = r.status_code
            desc = STATUS_DESC.get(status, f"Código {status}")
            
            # Obtener CVEs y recomendación
            cves = get_cves_for_path(cms, status, path)
            recommendation = get_recommendation(status, path)
            
            # Determinar color según status
            if status == 200:
                color = GREEN
                safe_download(url, cms)
            elif status == 403:
                color = CYAN
            elif status in (301, 302):
                color = ORANGE
            elif 400 <= status < 500:
                color = RED
            else:
                color = ""
            
            if color and status != 404:  # Solo mostrar si no es 404
                print(f"{color}[+]{RESET} {cms} {path} ({status}) {desc}")
            
            results.append({
                "CMS": cms,
                "Ruta": path,
                "HTTP": status,
                "Estado": desc,
                "CVE": cves,
                "Recomendacion": recommendation
            })
            
        except requests.exceptions.Timeout:
            results.append({
                "CMS": cms,
                "Ruta": path,
                "HTTP": "TIMEOUT",
                "Estado": "Timeout",
                "CVE": "N/A",
                "Recomendacion": "Revisar timeout de conexión"
            })
        except Exception as e:
            results.append({
                "CMS": cms,
                "Ruta": path,
                "HTTP": "ERROR",
                "Estado": str(e)[:50],
                "CVE": "N/A",
                "Recomendacion": "Revisar conectividad"
            })
        
        time.sleep(0.1)  # Pequeña pausa para no sobrecargar
    
    print()  # Nueva línea después del progreso
    return results

# =======================
# EXPORTAR RESULTADOS CSV
# =======================
def export_csv(results, target):
    if not results:
        print(f"{RED}[!]{RESET} No hay resultados para exportar")
        return
    
    csv_file = "cms_audit_results.csv"
    try:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"{GREEN}[✓]{RESET} CSV exportado: {csv_file}")
    except Exception as e:
        print(f"{RED}[!]{RESET} Error exportando CSV: {e}")

# =======================
# EXPORTAR RESULTADOS HTML
# =======================
def export_html(results, target):
    if not results:
        return
    
    html_file = "cms_audit_results.html"
    try:
        with open(html_file, "w", encoding="utf-8") as f:
            # Encabezado HTML
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Resultados Auditoría CMS - {target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 95%;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 40px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 5px solid #3498db;
        }}
        .summary-item {{
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }}
        th {{
            background-color: #2c3e50;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .critical {{
            background-color: #ffcccc !important;
            font-weight: bold;
        }}
        .warning {{
            background-color: #fff3cd !important;
        }}
        .info {{
            background-color: #d1ecf1 !important;
        }}
        .ok {{
            background-color: #d4edda !important;
        }}
        .status-200 {{
            color: #d63031;
            font-weight: bold;
        }}
        .status-403 {{
            color: #e67e22;
        }}
        .status-301, .status-302 {{
            color: #f39c12;
        }}
        .status-404 {{
            color: #27ae60;
        }}
        .cve {{
            font-family: monospace;
            font-size: 12px;
            color: #c0392b;
            background-color: #f9ebea;
            padding: 2px 5px;
            border-radius: 3px;
            margin: 2px;
            display: inline-block;
        }}
        .recommendation {{
            font-style: italic;
            color: #2c3e50;
            background-color: #e8f4fc;
            padding: 8px;
            border-left: 3px solid #3498db;
            margin-top: 5px;
            border-radius: 0 3px 3px 0;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 12px;
            text-align: center;
        }}
        .timestamp {{
            float: right;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .severity {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
        }}
        .severity-critical {{
            background-color: #d63031;
            color: white;
        }}
        .severity-high {{
            background-color: #e74c3c;
            color: white;
        }}
        .severity-medium {{
            background-color: #f39c12;
            color: white;
        }}
        .severity-low {{
            background-color: #3498db;
            color: white;
        }}
        .severity-info {{
            background-color: #95a5a6;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Reporte de Auditoría de Seguridad CMS <span class="timestamp">{time.strftime('%Y-%m-%d %H:%M:%S')}</span></h1>
        
        <div class="summary">
            <h2>📋 Resumen General</h2>
            <div class="summary-item"><strong>URL Objetivo:</strong> {target}</div>
            <div class="summary-item"><strong>CMS Detectado:</strong> {results[0]['CMS'] if results else 'No detectado'}</div>
            <div class="summary-item"><strong>Total Rutas Escaneadas:</strong> {len(results)}</div>
""")
            
            # Estadísticas
            status_counts = {}
            critical_count = 0
            
            for r in results:
                status = r.get("HTTP", "")
                status_counts[status] = status_counts.get(status, 0) + 1
                if status == 200:
                    critical_count += 1
            
            f.write(f"""
            <div class="summary-item"><strong>Rutas Críticas (HTTP 200):</strong> {critical_count}</div>
            <div class="summary-item"><strong>Rutas Protegidas (HTTP 403):</strong> {status_counts.get(403, 0)}</div>
            <div class="summary-item"><strong>Rutas No Encontradas (HTTP 404):</strong> {status_counts.get(404, 0)}</div>
            <div class="summary-item"><strong>Rutas con Redirección:</strong> {status_counts.get(301, 0) + status_counts.get(302, 0)}</div>
        </div>
        
        <h2>📈 Resultados Detallados</h2>
        <table>
            <thead>
                <tr>
                    <th width="100px">CMS</th>
                    <th width="250px">Ruta</th>
                    <th width="80px">HTTP</th>
                    <th width="120px">Estado</th>
                    <th width="200px">CVE</th>
                    <th width="300px">Recomendación</th>
                </tr>
            </thead>
            <tbody>
""")
            
            # Filas de resultados
            for r in results:
                status = r.get("HTTP", "")
                cms = r.get("CMS", "")
                path = r.get("Ruta", "")
                estado = r.get("Estado", "")
                cves = r.get("CVE", "")
                recomendacion = r.get("Recomendacion", "")
                
                # Determinar clase CSS
                row_class = ""
                if status == 200:
                    row_class = "critical"
                elif status == 403:
                    row_class = "warning"
                elif status in (301, 302):
                    row_class = "info"
                elif status == 404:
                    row_class = "ok"
                
                # Clase para estado HTTP
                status_class = f"status-{status}" if isinstance(status, int) else ""
                
                f.write(f"""
                <tr class="{row_class}">
                    <td><strong>{cms}</strong></td>
                    <td><code>{path}</code></td>
                    <td class="{status_class}">{status}</td>
                    <td>{estado}</td>
                    <td>""")
                
                # Mostrar CVEs como badges
                if cves and cves != "N/A":
                    for cve in cves.split(", "):
                        f.write(f'<span class="cve">{cve}</span> ')
                
                f.write(f"""</td>
                    <td><div class="recommendation">{recomendacion}</div></td>
                </tr>""")
            
            f.write("""
            </tbody>
        </table>
        
        <div class="summary">
            <h2>🛡️ Recomendaciones de Seguridad</h2>
            <div class="summary-item"><strong>1. Archivos Críticos:</strong> Mover archivos de configuración fuera del directorio web público.</div>
            <div class="summary-item"><strong>2. Permisos:</strong> Aplicar principio de mínimo privilegio en permisos de archivos.</div>
            <div class="summary-item"><strong>3. Hardening:</strong> Configurar correctamente el servidor web (.htaccess, web.config).</div>
            <div class="summary-item"><strong>4. Backup:</strong> Eliminar archivos de backup del entorno de producción.</div>
            <div class="summary-item"><strong>5. Monitoreo:</strong> Implementar monitoreo de accesos no autorizados.</div>
            <div class="summary-item"><strong>6. Actualizaciones:</strong> Mantener el CMS y plugins actualizados.</div>
        </div>
        
        <div class="footer">
            <p>🔒 <strong>CMS Security Scanner v2.0</strong> - Reporte generado automáticamente</p>
            <p>⚠️ Este reporte identifica vulnerabilidades potenciales. Se recomienda revisión por un profesional de seguridad.</p>
            <p>📅 Fecha de generación: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>""")
        
        print(f"{GREEN}[✓]{RESET} HTML exportado: {html_file}")
        
        # Resumen estadístico
        print(f"\n{BLUE}[*]{RESET} Resumen estadístico:")
        print(f"  {GREEN}✓{RESET} Rutas críticas (200): {critical_count}")
        print(f"  {CYAN}⚠{RESET} Rutas protegidas (403): {status_counts.get(403, 0)}")
        print(f"  {ORANGE}↪{RESET} Rutas con redirección: {status_counts.get(301, 0) + status_counts.get(302, 0)}")
        print(f"  {BLUE}✓{RESET} Rutas no encontradas (404): {status_counts.get(404, 0)}")
        
    except Exception as e:
        print(f"{RED}[!]{RESET} Error exportando HTML: {e}")

# =======================
# MAIN
# =======================
def main():
    print(f"{BLUE}============================================={RESET}")
    print(f"{BLUE}        CMS SECURITY SCANNER v2.0           {RESET}")
    print(f"{BLUE}============================================={RESET}\n")
    
    # Obtener URL objetivo
    if len(sys.argv) > 1:
        target = sys.argv[1].strip()
    else:
        target = input(f"{BLUE}[?]{RESET} Dominio o URL objetivo: ").strip()
    
    if not target:
        print(f"{RED}[!]{RESET} No se proporcionó URL objetivo")
        return
    
    if not target.startswith("http"):
        target = "http://" + target
    target = target.rstrip("/")
    
    print(f"\n{BLUE}[*]{RESET} Objetivo: {target}")
    
    # Detectar CMS
    detected_cms = detect_cms(target)
    print(f"\n{GREEN}[✓]{RESET} CMS detectado: {detected_cms}")
    
    # Escanear rutas específicas del CMS detectado
    results = scan_paths(target, detected_cms)
    
    # Exportar resultados
    export_csv(results, target)
    export_html(results, target)
    
    # Resumen final
    print(f"\n{GREEN}[✓]{RESET} Auditoría finalizada")
    print(f"{BLUE}[*]{RESET} Rutas encontradas: {len([r for r in results if r['HTTP'] in [200, 301, 302, 403]])}")
    print(f"{BLUE}[*]{RESET} Archivos descargados en: ./{DOWNLOAD_DIR}/")
    print(f"{BLUE}[*]{RESET} Archivos de reporte: cms_audit_results.csv, cms_audit_results.html")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} Escaneo interrumpido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!]{RESET} Error fatal: {e}")
        sys.exit(1)