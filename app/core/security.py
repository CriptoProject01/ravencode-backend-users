"""
Security utilities for input validation and sanitization.
Protects against NoSQL injection attacks.
"""
import re
from typing import Any, Dict
from fastapi import HTTPException, status


class SecurityValidator:
    """Validates and sanitizes user inputs to prevent NoSQL injection."""
    
    # Patrones peligrosos en NoSQL injection
    NOSQL_OPERATORS = [
        "$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin",
        "$and", "$or", "$not", "$nor", "$exists", "$type",
        "$regex", "$where", "$expr", "$jsonSchema", "$mod",
        "$text", "$search", "$language", "$caseSensitive",
        "$diacriticSensitive"
    ]
    
    @staticmethod
    def sanitize_string(value: str, field_name: str = "input") -> str:
        """
        Sanitiza strings eliminando caracteres peligrosos.
        
        Args:
            value: String a sanitizar
            field_name: Nombre del campo para mensajes de error
            
        Returns:
            str: String sanitizado
            
        Raises:
            HTTPException: Si el input contiene caracteres peligrosos
        """
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} must be a string"
            )
        
        # Verificar operadores NoSQL
        if any(op in value for op in SecurityValidator.NOSQL_OPERATORS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid characters detected in {field_name}"
            )
        
        # Verificar caracteres especiales de MongoDB
        dangerous_chars = ['$', '{', '}']
        if any(char in value for char in dangerous_chars):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid characters detected in {field_name}"
            )
        
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> str:
        """
        Valida formato de email y sanitiza.
        
        Args:
            email: Email a validar
            
        Returns:
            str: Email validado y sanitizado
            
        Raises:
            HTTPException: Si el email es inválido
        """
        # Sanitizar primero
        email = SecurityValidator.sanitize_string(email, "email")
        
        # Validar formato con regex estricto
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Convertir a minúsculas para consistencia
        return email.lower()