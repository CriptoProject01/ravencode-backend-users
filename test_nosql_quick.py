"""
Script simple y directo para probar la protección NoSQL Injection.
Prueba manual de casos específicos.
"""

import requests
import json

BASE_URL = "http://localhost:8001/auth"

print("=" * 70)
print("PRUEBA RÁPIDA - PROTECCIÓN NOSQL INJECTION")
print("=" * 70)

# Test 1: Operador $ne en email
print("\n[TEST 1] Intento de login con operador $ne")
print("Payload: {\"email\": {\"$ne\": \"\"}, \"password\": \"test\"}")
try:
    payload = {
        "email": {"$ne": ""},
        "password": "cualquierCosa",
        "recaptcha_token": "test_token"
    }
    response = requests.post(f"{BASE_URL}/login", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Respuesta: {response.json()}")
    if response.status_code == 422:
        print("✅ BLOQUEADO - Validación de tipo de dato")
    elif response.status_code == 400:
        print("✅ BLOQUEADO - Validación de seguridad")
    else:
        print("⚠️  ADVERTENCIA - No bloqueado correctamente")
except Exception as e:
    print(f"✅ EXCEPCIÓN - {e}")

# Test 2: Operador $where en string
print("\n[TEST 2] Intento de registro con $where en nombre")
print("Payload: nombre con '$where'")
try:
    payload = {
        "nombre": "Juan$where",
        "email": "test_nosql@example.com",
        "password": "Test123!",
        "fecha_de_nacimiento": "2005-01-01",
        "institucion_educativa": "Colegio Test",
        "grado_academico": "9",
        "recaptcha_token": "test_token"
    }
    response = requests.post(f"{BASE_URL}/register", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Respuesta: {response.json()}")
    if "Invalid characters" in str(response.json()):
        print("✅ BLOQUEADO - Detectó operador NoSQL")
    else:
        print("⚠️  Revisar respuesta")
except Exception as e:
    print(f"Error: {e}")

# Test 3: Caracteres especiales $ en email
print("\n[TEST 3] Intento de login con $ en email")
print("Payload: email con carácter $")
try:
    payload = {
        "email": "admin$test@example.com",
        "password": "password",
        "recaptcha_token": "test_token"
    }
    response = requests.post(f"{BASE_URL}/login", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Respuesta: {response.json()}")
    if "Invalid characters" in str(response.json()):
        print("✅ BLOQUEADO - Detectó carácter peligroso")
    else:
        print("⚠️  Revisar respuesta")
except Exception as e:
    print(f"Error: {e}")

# Test 4: Llaves {} en campo de texto
print("\n[TEST 4] Intento de registro con llaves {} en institución")
print("Payload: institución con {}")
try:
    payload = {
        "nombre": "María Test",
        "email": "maria_test@example.com",
        "password": "Test123!",
        "fecha_de_nacimiento": "2005-01-01",
        "institucion_educativa": "Colegio {test}",
        "grado_academico": "10",
        "recaptcha_token": "test_token"
    }
    response = requests.post(f"{BASE_URL}/register", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Respuesta: {response.json()}")
    if "Invalid characters" in str(response.json()):
        print("✅ BLOQUEADO - Detectó llaves peligrosas")
    else:
        print("⚠️  Revisar respuesta")
except Exception as e:
    print(f"Error: {e}")

# Test 5: Email válido (debe funcionar)
print("\n[TEST 5] Registro con email VÁLIDO")
print("Payload: email normal sin caracteres peligrosos")
try:
    payload = {
        "nombre": "Pedro Válido",
        "email": "pedro.valido@example.com",
        "password": "Test123!",
        "fecha_de_nacimiento": "2005-01-01",
        "institucion_educativa": "Colegio Nacional",
        "grado_academico": "11",
        "recaptcha_token": "test_token"
    }
    response = requests.post(f"{BASE_URL}/register", json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Respuesta: {response.json()}")
    if "Invalid characters" in str(response.json()):
        print("❌ FALSO POSITIVO - Email válido bloqueado incorrectamente")
    elif "reCAPTCHA" in str(response.json()) or "already" in str(response.json()).lower():
        print("✅ OK - Email válido procesado (falla por reCAPTCHA o ya existe, no por inyección)")
    else:
        print("✅ OK - Email válido procesado correctamente")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 70)
print("PRUEBAS COMPLETADAS")
print("=" * 70)
print("\nRESUMEN:")
print("✅ = Protección funcionando correctamente")
print("⚠️  = Requiere revisión")
print("❌ = Falso positivo detectado")
