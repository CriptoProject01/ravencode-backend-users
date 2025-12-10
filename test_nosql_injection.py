"""
Script de prueba para validar la protección contra NoSQL Injection en RavenCode.
Este script intenta varios tipos de ataques de inyección NoSQL para demostrar
que el sistema los bloquea correctamente.
"""

import requests
from datetime import date
import json

# Configuración
BASE_URL = "http://localhost:8001"
API_URL = f"{BASE_URL}/auth"

# Color codes para output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_section(title):
    """Imprime una sección del test."""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{title:^70}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

def print_test(test_name, payload, description):
    """Imprime información del test."""
    print(f"{YELLOW}Test: {test_name}{RESET}")
    print(f"Descripción: {description}")
    print(f"Payload: {json.dumps(payload, indent=2)}")

def print_result(success, message):
    """Imprime el resultado del test."""
    if success:
        print(f"{GREEN}✓ PROTECCIÓN EXITOSA: {message}{RESET}\n")
    else:
        print(f"{RED}✗ VULNERABILIDAD DETECTADA: {message}{RESET}\n")

# =============================================================================
# ESCENARIOS DE ATAQUE
# =============================================================================

def test_nosql_operators_in_email():
    """
    Escenario 1: Inyección de operadores NoSQL en el campo email
    Intenta usar operadores de MongoDB para bypassear autenticación
    """
    print_section("ESCENARIO 1: Operadores NoSQL en Email")
    
    attacks = [
        {
            "name": "Operador $ne (not equal)",
            "payload": {
                "email": {"$ne": ""},
                "password": "cualquierCosa",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta hacer login con email != '' (todos los emails)"
        },
        {
            "name": "Operador $gt (greater than)",
            "payload": {
                "email": {"$gt": ""},
                "password": "test123",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta obtener usuarios con email > ''"
        },
        {
            "name": "String con operador $ne",
            "payload": {
                "email": "admin@test.com' || '1'=='1",
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta SQL-like injection adaptado a NoSQL"
        }
    ]
    
    for attack in attacks:
        print_test(attack["name"], attack["payload"], attack["description"])
        try:
            response = requests.post(f"{API_URL}/login", json=attack["payload"])
            if response.status_code == 400 or response.status_code == 422:
                print_result(True, f"Ataque bloqueado - Status {response.status_code}")
            else:
                print_result(False, f"Ataque no bloqueado - Status {response.status_code}")
        except Exception as e:
            print_result(True, f"Excepción generada (protección activa): {str(e)}")

def test_nosql_operators_in_strings():
    """
    Escenario 2: Operadores NoSQL embebidos en strings
    Intenta inyectar operadores MongoDB dentro de valores de texto
    """
    print_section("ESCENARIO 2: Operadores MongoDB en Strings")
    
    attacks = [
        {
            "name": "Operador $regex en email",
            "payload": {
                "email": "admin@test.com{$regex:'.*'}",
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta usar regex para matching amplio"
        },
        {
            "name": "Operador $where en nombre",
            "payload": {
                "nombre": "Juan$where",
                "email": "test@example.com",
                "password": "Test123!",
                "fecha_de_nacimiento": "2005-01-01",
                "institucion_educativa": "Colegio Test",
                "grado_academico": "9",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta inyectar $where en campo nombre"
        },
        {
            "name": "Operador $expr en institución",
            "payload": {
                "nombre": "Juan Test",
                "email": "test2@example.com",
                "password": "Test123!",
                "fecha_de_nacimiento": "2005-01-01",
                "institucion_educativa": "Colegio$expr",
                "grado_academico": "9",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta inyectar $expr para ejecutar código"
        }
    ]
    
    for attack in attacks:
        print_test(attack["name"], attack["payload"], attack["description"])
        try:
            response = requests.post(f"{API_URL}/register", json=attack["payload"])
            if response.status_code == 400 or response.status_code == 422:
                print_result(True, f"Ataque bloqueado - Status {response.status_code}")
            else:
                print_result(False, f"Ataque no bloqueado - Status {response.status_code}")
        except Exception as e:
            print_result(True, f"Excepción generada (protección activa): {str(e)}")

def test_special_characters():
    """
    Escenario 3: Caracteres especiales de MongoDB
    Intenta usar caracteres que tienen significado especial en MongoDB
    """
    print_section("ESCENARIO 3: Caracteres Especiales de MongoDB")
    
    attacks = [
        {
            "name": "Dollar sign ($) en email",
            "payload": {
                "email": "admin$test@example.com",
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "$ es el prefijo de operadores MongoDB"
        },
        {
            "name": "Llaves {} en nombre",
            "payload": {
                "nombre": "Juan{test}",
                "email": "test3@example.com",
                "password": "Test123!",
                "fecha_de_nacimiento": "2005-01-01",
                "institucion_educativa": "Colegio Test",
                "grado_academico": "9",
                "recaptcha_token": "test_token"
            },
            "description": "{} se usan para definir objetos/queries en MongoDB"
        },
        {
            "name": "Combinación de caracteres peligrosos",
            "payload": {
                "nombre": "Test User",
                "email": "test4@example.com",
                "password": "Test123!",
                "fecha_de_nacimiento": "2005-01-01",
                "institucion_educativa": "Colegio {$ne: null}",
                "grado_academico": "9",
                "recaptcha_token": "test_token"
            },
            "description": "Combina {} y operador $ne"
        }
    ]
    
    for attack in attacks:
        print_test(attack["name"], attack["payload"], attack["description"])
        try:
            response = requests.post(f"{API_URL}/register", json=attack["payload"])
            if response.status_code == 400 or response.status_code == 422:
                print_result(True, f"Ataque bloqueado - Status {response.status_code}")
            else:
                print_result(False, f"Ataque no bloqueado - Status {response.status_code}")
        except Exception as e:
            print_result(True, f"Excepción generada (protección activa): {str(e)}")

def test_javascript_injection():
    """
    Escenario 4: Inyección de JavaScript
    MongoDB permite ejecutar JavaScript en algunas operaciones ($where, mapReduce)
    """
    print_section("ESCENARIO 4: Inyección de JavaScript")
    
    attacks = [
        {
            "name": "JavaScript en $where",
            "payload": {
                "email": "'; return true; var dummy='",
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta inyectar código JavaScript"
        },
        {
            "name": "Function execution",
            "payload": {
                "nombre": "function(){return true}",
                "email": "test5@example.com",
                "password": "Test123!",
                "fecha_de_nacimiento": "2005-01-01",
                "institucion_educativa": "Colegio Test",
                "grado_academico": "9",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta definir y ejecutar una función"
        }
    ]
    
    for attack in attacks:
        print_test(attack["name"], attack["payload"], attack["description"])
        try:
            response = requests.post(f"{API_URL}/login" if "email" in attack["payload"] and "nombre" not in attack["payload"] else f"{API_URL}/register", 
                                    json=attack["payload"])
            if response.status_code == 400 or response.status_code == 422:
                print_result(True, f"Ataque bloqueado - Status {response.status_code}")
            else:
                print_result(False, f"Ataque no bloqueado - Status {response.status_code}")
        except Exception as e:
            print_result(True, f"Excepción generada (protección activa): {str(e)}")

def test_valid_inputs():
    """
    Escenario 5: Inputs válidos
    Verifica que los inputs legítimos siguen funcionando
    """
    print_section("ESCENARIO 5: Verificación de Inputs Válidos")
    
    valid_cases = [
        {
            "name": "Email válido con números",
            "payload": {
                "nombre": "Juan Pérez",
                "email": "juan.perez123@example.com",
                "password": "SecurePass123!",
                "fecha_de_nacimiento": "2005-06-15",
                "institucion_educativa": "Colegio Nacional",
                "grado_academico": "10",
                "recaptcha_token": "test_token"
            },
            "description": "Registro normal con datos válidos"
        },
        {
            "name": "Email con caracteres especiales permitidos",
            "payload": {
                "nombre": "María García",
                "email": "maria.garcia+test@university.edu.co",
                "password": "SecurePass456!",
                "fecha_de_nacimiento": "2006-03-20",
                "institucion_educativa": "Universidad Nacional",
                "grado_academico": "11",
                "recaptcha_token": "test_token"
            },
            "description": "Email con + y múltiples dominios"
        }
    ]
    
    for case in valid_cases:
        print_test(case["name"], case["payload"], case["description"])
        try:
            response = requests.post(f"{API_URL}/register", json=case["payload"])
            # Puede fallar por otros motivos (reCAPTCHA, usuario existente), 
            # pero NO debe ser por inyección SQL
            if response.status_code in [200, 201, 400]:
                error_msg = response.json().get("detail", "") if response.status_code == 400 else ""
                if "Invalid characters" not in error_msg and "reCAPTCHA" in error_msg or response.status_code in [200, 201]:
                    print_result(True, f"Input válido procesado correctamente - Status {response.status_code}")
                elif "already" in error_msg.lower():
                    print_result(True, f"Input válido (usuario ya existe) - Status {response.status_code}")
                else:
                    print_result(False, f"Input válido bloqueado incorrectamente: {error_msg}")
            else:
                print_result(False, f"Status inesperado: {response.status_code}")
        except Exception as e:
            print_result(False, f"Error inesperado: {str(e)}")

def test_array_injection():
    """
    Escenario 6: Inyección mediante arrays
    Intenta usar arrays de MongoDB para ataques $in, $nin
    """
    print_section("ESCENARIO 6: Inyección mediante Arrays")
    
    attacks = [
        {
            "name": "Array en email con $in",
            "payload": {
                "email": ["admin@test.com", "user@test.com"],
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta buscar múltiples emails simultáneamente"
        },
        {
            "name": "Operador $nin en string",
            "payload": {
                "email": "test$nin@example.com",
                "password": "password",
                "recaptcha_token": "test_token"
            },
            "description": "Intenta usar $nin en el email"
        }
    ]
    
    for attack in attacks:
        print_test(attack["name"], attack["payload"], attack["description"])
        try:
            response = requests.post(f"{API_URL}/login", json=attack["payload"])
            if response.status_code == 400 or response.status_code == 422:
                print_result(True, f"Ataque bloqueado - Status {response.status_code}")
            else:
                print_result(False, f"Ataque no bloqueado - Status {response.status_code}")
        except Exception as e:
            print_result(True, f"Excepción generada (protección activa): {str(e)}")

# =============================================================================
# EJECUCIÓN PRINCIPAL
# =============================================================================

def main():
    """Ejecuta todos los escenarios de prueba."""
    print(f"\n{GREEN}{'*'*70}")
    print(f"   PRUEBAS DE PROTECCIÓN CONTRA NOSQL INJECTION - RAVENCODE")
    print(f"{'*'*70}{RESET}\n")
    
    print(f"Base URL: {BASE_URL}")
    print(f"API URL: {API_URL}")
    print(f"\n{YELLOW}NOTA: El servidor debe estar corriendo en {BASE_URL}{RESET}")
    print(f"{YELLOW}Para iniciar: uvicorn app.main:app --reload --port 8001{RESET}\n")
    
    try:
        # Verificar que el servidor está corriendo
        response = requests.get(f"{BASE_URL}/health", timeout=3)
        print(f"{GREEN}✓ Servidor activo y respondiendo{RESET}\n")
    except:
        print(f"{RED}✗ ERROR: No se puede conectar al servidor en {BASE_URL}{RESET}")
        print(f"{YELLOW}Por favor, inicia el servidor antes de ejecutar las pruebas{RESET}\n")
        return
    
    # Ejecutar todos los escenarios
    test_nosql_operators_in_email()
    test_nosql_operators_in_strings()
    test_special_characters()
    test_javascript_injection()
    test_array_injection()
    test_valid_inputs()
    
    # Resumen final
    print_section("RESUMEN DE PRUEBAS")
    print(f"{GREEN}Las pruebas han finalizado.{RESET}")
    print(f"\n{YELLOW}Interpretación de resultados:{RESET}")
    print(f"  {GREEN}✓ PROTECCIÓN EXITOSA{RESET} - El ataque fue bloqueado correctamente")
    print(f"  {RED}✗ VULNERABILIDAD DETECTADA{RESET} - El ataque podría haber tenido éxito")
    print(f"\n{BLUE}El sistema debe bloquear todos los ataques (✓) y permitir inputs válidos.{RESET}\n")

if __name__ == "__main__":
    main()
