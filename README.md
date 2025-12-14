# CMS_PATHS

## 🎯 Propósito Principal
Este script es un scanner de seguridad automatizado que identifica y reporta vulnerabilidades potenciales en sistemas de gestión de contenido (CMS) mediante la detección de archivos y rutas sensibles expuestas públicamente.
Identifica archivos de configuracion y que podrian llegar a tener credenciales de bases de datos.

<img width="408" height="758" alt="Image" src="https://github.com/user-attachments/assets/4bc2453e-4109-4da3-95d2-73dc0761fd12" />

<img width="1854" height="848" alt="Image" src="https://github.com/user-attachments/assets/e9f3818d-a753-4914-a64e-6a0b49d23a55" />

<img width="1834" height="772" alt="Image" src="https://github.com/user-attachments/assets/36bbd7dc-7883-44cd-a878-d36f78266a98" />



🔍 Flujo de Ejecución
1. Fase de Detección (Reconocimiento)
text
Entrada URL → Análisis del sitio → Identificación del CMS → Selección de rutas específicas
Detecta automáticamente qué CMS está usando el sitio (WordPress, Drupal, Joomla, etc.)

Utiliza múltiples técnicas: análisis de HTML, headers HTTP, URLs características, cookies

Si no detecta un CMS específico, usa rutas genéricas comunes

2. Fase de Escaneo (Enumeration)
text
CMS detectado → Lista de rutas específicas → Prueba cada ruta → Clasifica resultados
Prueba cientos de rutas conocidas para el CMS detectado

Verifica archivos de configuración, backups, paneles administrativos, logs, etc.

Clasifica resultados según el código HTTP obtenido (200, 403, 404, etc.)

3. Fase de Análisis (Intelligence)
text
Resultados brutos → Asocia CVEs → Genera recomendaciones → Produce reportes
Vincula cada hallazgo con vulnerabilidades conocidas (CVEs específicos)

Genera recomendaciones de remediación personalizadas

Clasifica por criticidad (crítico, alto, medio, bajo)

4. Fase de Reporte (Documentation)
text
Datos estructurados → Exporta CSV → Genera HTML → Proporciona resumen
Crea reportes profesionales en múltiples formatos

Incluye estadísticas, resúmenes ejecutivos y detalles técnicos

Ofrece una visión clara de los riesgos identificados

📊 Características Clave
Base de Conocimiento Integrada
python
# Contiene inteligencia predefinida:
- 1,000+ rutas específicas por CMS
- 50+ vulnerabilidades conocidas (CVEs) mapeadas
- Recomendaciones de remediación contextuales
Sistema de Clasificación Inteligente
python
# Clasifica automáticamente:
- 200 → CRÍTICO: Archivo accesible públicamente
- 403 → ALTO: Existe pero protegido
- 301/302 → MEDIO: Redirecciones
- 404 → BAJO: No existe (estado deseado)
Reportes Profesionales
HTML: Diseño visual con colores, estadísticas, resúmenes ejecutivos

CSV: Datos estructurados para análisis posterior

Consola: Feedback en tiempo real con colores

🛡️ Valor de Seguridad
Para Equipos de Desarrollo
Identifica configuraciones inseguras antes de llegar a producción

Automatiza revisiones de seguridad repetitivas

Educa sobre prácticas seguras específicas para cada CMS

Para Auditores de Seguridad
Acelera auditorías iniciales de reconocimiento

Proporciona evidencia estructurada de vulnerabilidades

Prioriza hallazgos por criticidad

Para Administradores de Sistemas
Monitorea el estado de seguridad de forma continua

Detecta archivos olvidados (backups, logs, instaladores)

Cumple con requerimientos de hardening básico

⚙️ Arquitectura Técnica
Componentes Principales
text
├── Detector CMS (fingerprinting)
├── Escáner Rutas (fuzzing controlado)
├── Motor CVEs (base de conocimiento)
├── Generador Reportes (output formats)
└── Gestor Descargas (evidence collection)
Diseño Modular
Extensible: Fácil agregar nuevos CMS o rutas

Configurable: Timeouts, límites, formatos ajustables

Resiliente: Manejo de errores y timeouts

🎨 Metáfora del Script
Piensa en este script como un "doctor de sitios web" que:

Diagnostica (¿qué CMS tienes?)

Examina (¿qué partes sensibles están expuestas?)

Identifica enfermedades (¿qué vulnerabilidades afectan?)

Receta tratamiento (¿cómo solucionarlo?)

Entrega informe médico (documentación completa)

🔬 Casos de Uso Típicos
1. Auditoría de Seguridad Inicial
bash
# Evaluar un nuevo sitio antes del lanzamiento
python3 cms_scanner.py https://mi-nuevo-sitio.com
2. Monitoreo Continuo
bash
# Verificar cambios no autorizados periódicamente
python3 cms_scanner.py https://sitio-en-produccion.com
3. Evaluación Post-Incidente
bash
# Después de un ataque, identificar vectores de entrada
python3 cms_scanner.py https://sitio-comprometido.com
4. Educación y Concientización
bash
# Mostrar a desarrolladores riesgos comunes
python3 cms_scanner.py https://sitio-de-prueba.com
⚠️ Consideraciones Éticas y Legales
ÚSALO RESPONSABLEMENTE:
Solo en sitios que posees o tienes permiso explícito

No para atacar sistemas de terceros

Para educación y mejora de seguridad propia

LIMITACIONES TÉCNICAS:
No es un escáner de vulnerabilidades completo

No prueba exploits, solo exposición de archivos

Depende de listas de rutas conocidas

📈 Métricas de Éxito
Un escaneo exitoso proporciona:

Lista priorizada de problemas de seguridad

Evidencia descargable de archivos expuestos

Recomendaciones accionables para corrección

Línea base para comparar mejoras futuras

🚀 En Resumen
Este script es una herramienta de fuerza multiplicadora que combina:

Reconocimiento automatizado (qué hay)

Análisis contextual (qué significa)

Documentación profesional (qué hacer)

Transforma horas de trabajo manual en segundos de ejecución automatizada, proporcionando a equipos técnicos y no técnicos una visión clara y accionable del estado de seguridad de sus aplicaciones web basadas en CMS.

Esencialmente: Automatiza lo aburrido, enfoca en lo importante, documenta lo crítico.
