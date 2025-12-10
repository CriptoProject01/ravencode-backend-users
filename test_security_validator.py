"""
Script de prueba directa para SecurityValidator sin pasar por reCAPTCHA.
Prueba las funciones de validación y sanitización directamente.
"""

import sys
sys.path.append('.')

from app.core.security import SecurityValidator
from fastapi import HTTPException

# Color codes para output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_section(title):
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{title:^70}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

def test_case(name, test_func, should_fail=True):
    """Ejecuta un caso de prueba."""
    try:
        result = test_func()
        if should_fail:
            print(f"{RED}✗ FALLÓ: {name}{RESET}")
            print(f"   Resultado: {result}")
            print(f"   Esperaba: Excepción HTTPException")
        else:
            print(f"{GREEN}✓ PASÓ: {name}{RESET}")
            print(f"   Resultado: {result}")
    except HTTPException as e:
        if should_fail:
            print(f"{GREEN}✓ PASÓ: {name}{RESET}")
            print(f"   Bloqueado correctamente: {e.detail}")
        else:
            print(f"{RED}✗ FALLÓ: {name}{RESET}")
            print(f"   Error inesperado: {e.detail}")
    except Exception as e:
        print(f"{RED}✗ ERROR: {name}{RESET}")
        print(f"   Excepción: {type(e).__name__}: {e}")

print_section("PRUEBAS DE PROTECCIÓN NOSQL - SecurityValidator")

# =============================================================================
# TEST 1: Operadores NoSQL en Strings
# =============================================================================
print_section("TEST 1: Detección de Operadores NoSQL")

test_case(
    "Operador $where en string",
    lambda: SecurityValidator.sanitize_string("Juan$where", "nombre"),
    should_fail=True
)

test_case(
    "Operador $ne en string",
    lambda: SecurityValidator.sanitize_string("test$ne", "campo"),
    should_fail=True
)

test_case(
    "Operador $gt en string",
    lambda: SecurityValidator.sanitize_string("value$gt", "campo"),
    should_fail=True
)

test_case(
    "Operador $regex en string",
    lambda: SecurityValidator.sanitize_string("admin$regex", "campo"),
    should_fail=True
)

test_case(
    "Operador $expr en string",
    lambda: SecurityValidator.sanitize_string("data$expr", "campo"),
    should_fail=True
)

test_case(
    "Operador $or en string",
    lambda: SecurityValidator.sanitize_string("test$or", "campo"),
    should_fail=True
)

# =============================================================================
# TEST 2: Caracteres Especiales de MongoDB
# =============================================================================
print_section("TEST 2: Detección de Caracteres Especiales")

test_case(
    "Carácter $ en string",
    lambda: SecurityValidator.sanitize_string("admin$test", "campo"),
    should_fail=True
)

test_case(
    "Llave abierta { en string",
    lambda: SecurityValidator.sanitize_string("test{value", "campo"),
    should_fail=True
)

test_case(
    "Llave cerrada } en string",
    lambda: SecurityValidator.sanitize_string("test}value", "campo"),
    should_fail=True
)

test_case(
    "Llaves completas {} en string",
    lambda: SecurityValidator.sanitize_string("test{data}", "campo"),
    should_fail=True
)

test_case(
    "Combinación ${} en string",
    lambda: SecurityValidator.sanitize_string("test${value}", "campo"),
    should_fail=True
)

# =============================================================================
# TEST 3: Validación de Email con Operadores
# =============================================================================
print_section("TEST 3: Validación de Email - Ataques")

test_case(
    "Email con operador $ne",
    lambda: SecurityValidator.validate_email("admin$ne@test.com"),
    should_fail=True
)

test_case(
    "Email con $",
    lambda: SecurityValidator.validate_email("admin$@test.com"),
    should_fail=True
)

test_case(
    "Email con llaves",
    lambda: SecurityValidator.validate_email("admin{test}@test.com"),
    should_fail=True
)

test_case(
    "Email con operador $regex",
    lambda: SecurityValidator.validate_email("admin@test.com$regex"),
    should_fail=True
)

test_case(
    "Email con comillas y operador",
    lambda: SecurityValidator.validate_email("admin@test.com' || '1'=='1"),
    should_fail=True
)

# =============================================================================
# TEST 4: Inputs Válidos (deben pasar)
# =============================================================================
print_section("TEST 4: Inputs Válidos - Deben Pasar")

test_case(
    "Nombre normal",
    lambda: SecurityValidator.sanitize_string("Juan Pérez", "nombre"),
    should_fail=False
)

test_case(
    "Institución normal",
    lambda: SecurityValidator.sanitize_string("Colegio Nacional", "institucion"),
    should_fail=False
)

test_case(
    "Texto con espacios",
    lambda: SecurityValidator.sanitize_string("  Texto con espacios  ", "campo"),
    should_fail=False
)

test_case(
    "Email válido simple",
    lambda: SecurityValidator.validate_email("juan@example.com"),
    should_fail=False
)

test_case(
    "Email válido con números",
    lambda: SecurityValidator.validate_email("user123@test.com"),
    should_fail=False
)

test_case(
    "Email válido con punto",
    lambda: SecurityValidator.validate_email("juan.perez@example.com"),
    should_fail=False
)

test_case(
    "Email válido con +",
    lambda: SecurityValidator.validate_email("user+test@example.com"),
    should_fail=False
)

test_case(
    "Email válido con guión",
    lambda: SecurityValidator.validate_email("user-name@test-domain.com"),
    should_fail=False
)

test_case(
    "Email con subdominio",
    lambda: SecurityValidator.validate_email("user@mail.university.edu.co"),
    should_fail=False
)

# =============================================================================
# TEST 5: Casos Edge
# =============================================================================
print_section("TEST 5: Casos Edge")

test_case(
    "String vacío",
    lambda: SecurityValidator.sanitize_string("", "campo"),
    should_fail=False
)

test_case(
    "Email con mayúsculas (debe convertir a minúsculas)",
    lambda: SecurityValidator.validate_email("ADMIN@TEST.COM"),
    should_fail=False
)

test_case(
    "Email formato inválido",
    lambda: SecurityValidator.validate_email("notanemail"),
    should_fail=True
)

test_case(
    "Email sin @",
    lambda: SecurityValidator.validate_email("admin.test.com"),
    should_fail=True
)

test_case(
    "Email sin dominio",
    lambda: SecurityValidator.validate_email("admin@"),
    should_fail=True
)

# =============================================================================
# TEST 6: Operadores Avanzados
# =============================================================================
print_section("TEST 6: Operadores Avanzados de MongoDB")

advanced_operators = [
    "$gte", "$lte", "$in", "$nin", "$and", "$not", "$nor",
    "$exists", "$type", "$jsonSchema", "$mod", "$text",
    "$search", "$language", "$caseSensitive", "$diacriticSensitive"
]

for op in advanced_operators:
    test_case(
        f"Operador {op}",
        lambda o=op: SecurityValidator.sanitize_string(f"test{o}", "campo"),
        should_fail=True
    )

# =============================================================================
# RESUMEN
# =============================================================================
print_section("RESUMEN DE PRUEBAS")
print(f"{GREEN}Las pruebas directas de SecurityValidator han finalizado.{RESET}")
print(f"\n{YELLOW}Interpretación:{RESET}")
print(f"  {GREEN}✓ PASÓ{RESET} - La validación funciona como se esperaba")
print(f"  {RED}✗ FALLÓ{RESET} - La validación no funcionó correctamente")
print(f"\n{BLUE}Todos los ataques (should_fail=True) deben ser bloqueados.{RESET}")
print(f"{BLUE}Todos los inputs válidos (should_fail=False) deben pasar.{RESET}\n")
