# MA2005B_Equipo3Repositorio
Repositorio oficial del Equipo 3 para el desarrollo y entregables del Reto.

## Laboratorio de Pruebas para DNSSEC - Equipo 3

### Descripción del Proyecto
Implementación y validación de un laboratorio de pruebas para DNSSEC que demuestra la cadena de confianza criptográfica desde la raíz hasta los dominios finales. El proyecto verifica el cumplimiento de los RFCs de seguridad DNS (4033, 4034, 4035, 5155, 6605 y 8624) mediante un entorno aislado y controlado, analizando el comportamiento de resolvedores con y sin validación criptográfica.

**Materia:** Aplicación de Criptografía y Seguridad (MA2005B)  
**Profesor:** Alberto Francisco Martínez Herrera  
**Socio Formador:** NIC México  
**Representante:** César Steve Salas Santos
**Fecha:** Octubre 2026  
**Institución:** Instituto Tecnológico y de Estudios Superiores de Monterrey

---

## Integrantes del Equipo

**Alicia Sofía Bernádez Terrazas** | A01562634 

**Annette Abigail Choque Millán** | A00842260 

**Bianca Cordero Hernández** | A00840981 

**Mariana Hernández Jiménez** | A00841920 

**Nuria Muñoz Viana** | A01833488 

---

## Estructura del Repositorio

El repositorio está organizado de la siguiente manera para facilitar la revisión de los entregables y el código fuente:

```text
MA2005B_Equipo3Repositorio/
├── README.md
├── Codigo/
│   ├── verificador_dnssec_v2.py    # Herramienta de verificación automatizada
│   └── cadena_final.py             # Script de extracción de datos DNS
|   ├── Recursos/
│   |   ├── metricas_dnssec.tsv         # Métricas de validación DNSSEC
│   |   └── cadena_dnssec.tsv           # Datos de la cadena de confianza
└── Entregables/
    ├── Equipo3_Actividad1Reto.pdf
    ├── Equipo3_Actividad2Reto.pdf
    ├── Equipo3_Actividad3Reto.pdf
    ├── Equipo3_ReporteTecnico.pdf
    ├── Equipo3_ReporteEjecutivo.pdf
    ├── Equipo3_PresentaciónEjecutiva.pdf
    └── Equipo3_VideoExplicativo.pdf
