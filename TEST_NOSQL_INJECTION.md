# 🔒 Pruebas de Protección contra NoSQL Injection

## 📋 Descripción

Este documento describe las pruebas implementadas para validar la protección contra ataques de inyección NoSQL en el sistema RavenCode. El script `test_nosql_injection.py` ejecuta 6 escenarios diferentes con múltiples vectores de ataque para asegurar que el sistema está protegido adecuadamente.

## 🎯 Objetivo

Demostrar que la clase `SecurityValidator` en `app/core/security.py` protege efectivamente contra:
- Operadores NoSQL de MongoDB ($gt, $ne, $where, $regex, etc.)
- Caracteres especiales peligrosos ($, {, })
- Inyección de JavaScript
- Ataques mediante arrays
- Manipulación de queries de base de datos

## 🚀 Cómo Ejecutar las Pruebas

### Prerequisitos

1. **Servidor backend ejecutándose:**
```bash
cd ravencode-backend-users
python -m venv venv
venv\Scripts\activate  # En Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

2. **MongoDB ejecutándose** (puerto por defecto 27017)

3. **Dependencias instaladas:**
```bash
pip install requests
```

### Ejecución

En una terminal diferente (mientras el servidor está corriendo):

```bash
cd ravencode-backend-users
python test_nosql_injection.py
```

## 📊 Escenarios de Prueba

### **Escenario 1: Operadores NoSQL en Email**
Intenta inyectar operadores de MongoDB directamente en el campo email para bypassear la autenticación.

**Ataques probados:**
- `{"email": {"$ne": ""}}` - Intenta hacer login con cualquier email
- `{"email": {"$gt": ""}}` - Intenta obtener emails mayores que string vacío
- SQL-like injection adaptado a NoSQL

**Resultado esperado:** ✅ Todos bloqueados con status 400 o 422

### **Escenario 2: Operadores MongoDB en Strings**
Embebe operadores NoSQL dentro de valores de texto normales.

**Ataques probados:**
- `admin@test.com{$regex:'.*'}` - Regex para matching amplio
- `Juan$where` - Operador $where en nombre
- `Colegio$expr` - Operador $expr en institución

**Resultado esperado:** ✅ Detectados y bloqueados por `sanitize_string()`

### **Escenario 3: Caracteres Especiales de MongoDB**
Usa caracteres que tienen significado especial en MongoDB.

**Ataques probados:**
- `$` en email (prefijo de operadores)
- `{}` en nombre (delimitadores de objetos)
- Combinaciones de caracteres peligrosos

**Resultado esperado:** ✅ Bloqueados por validación de caracteres peligrosos

### **Escenario 4: Inyección de JavaScript**
Intenta inyectar y ejecutar código JavaScript (MongoDB permite JS en $where, mapReduce).

**Ataques probados:**
- `'; return true; var dummy='` - Inyección JavaScript
- `function(){return true}` - Definición de función

**Resultado esperado:** ✅ Bloqueados por detección de patrones

### **Escenario 5: Verificación de Inputs Válidos**
Confirma que inputs legítimos NO son bloqueados.

**Casos probados:**
- Email válido con números: `juan.perez123@example.com`
- Email con caracteres permitidos: `maria.garcia+test@university.edu.co`

**Resultado esperado:** ✅ Procesados correctamente (pueden fallar por otros motivos como reCAPTCHA, pero NO por inyección)

### **Escenario 6: Inyección mediante Arrays**
Intenta usar arrays para operadores $in, $nin.

**Ataques probados:**
- Arrays en email para buscar múltiples valores
- Operador $nin en string

**Resultado esperado:** ✅ Bloqueados por validación de tipo de dato

## 🔍 Interpretación de Resultados

### ✅ PROTECCIÓN EXITOSA (Verde)
```
✓ PROTECCIÓN EXITOSA: Ataque bloqueado - Status 400
```
El sistema detectó y bloqueó el ataque correctamente.

### ❌ VULNERABILIDAD DETECTADA (Rojo)
```
✗ VULNERABILIDAD DETECTADA: Ataque no bloqueado - Status 200
```
El ataque podría haber tenido éxito - requiere investigación.

## 🛡️ Mecanismos de Protección

### 1. **Validación de Email** (`SecurityValidator.validate_email`)
```python
# Sanitiza primero
email = SecurityValidator.sanitize_string(email, "email")

# Valida formato con regex estricto
email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
```

### 2. **Sanitización de Strings** (`SecurityValidator.sanitize_string`)
```python
# Verifica operadores NoSQL
NOSQL_OPERATORS = ["$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin",
                   "$and", "$or", "$not", "$nor", "$exists", "$type",
                   "$regex", "$where", "$expr", "$jsonSchema", "$mod"]

# Verifica caracteres especiales de MongoDB
dangerous_chars = ['$', '{', '}']
```

### 3. **Aplicación en Servicios**
Todos los métodos en `StudentService` y `AuthService` usan estos validadores:
```python
# En create_student, get_student_by_email, etc.
email = SecurityValidator.validate_email(email)

# En campos de texto
nombre = SecurityValidator.sanitize_string(nombre, "nombre")
```

## 📈 Resultados Esperados

Al ejecutar las pruebas completas, deberías ver:

```
✓ Escenario 1: Todos los ataques bloqueados (3/3)
✓ Escenario 2: Todos los ataques bloqueados (3/3)
✓ Escenario 3: Todos los ataques bloqueados (3/3)
✓ Escenario 4: Todos los ataques bloqueados (2/2)
✓ Escenario 5: Inputs válidos procesados (2/2)
✓ Escenario 6: Todos los ataques bloqueados (2/2)
```

## 🔧 Solución de Problemas

### Error: "No se puede conectar al servidor"
- Verifica que el backend está corriendo en puerto 8001
- Ejecuta: `uvicorn app.main:app --reload --port 8001`

### Error: "Could not connect to the database"
- Verifica que MongoDB está corriendo
- Verifica las variables de entorno en `.env`

### Algunos tests fallan por reCAPTCHA
- Esto es normal, estamos usando tokens de prueba
- Lo importante es que NO fallen por "Invalid characters detected"

## 📚 Referencias

- [OWASP NoSQL Injection](https://owasp.org/www-community/attacks/NoSQL_Injection)
- [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

## 👥 Equipo

Proyecto desarrollado por el equipo **Cuervos** - Universidad Nacional de Colombia
- Curso: Ingeniería de Software II
- Semestre: 2025-1
