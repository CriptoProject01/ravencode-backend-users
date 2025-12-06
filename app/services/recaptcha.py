"""
reCAPTCHA verification service for RavenCode.
This module provides functionality to verify reCAPTCHA tokens from Google.
"""
import requests
from typing import Dict, Any
from app.core.config import settings


class RecaptchaService:
    """Service for verifying Google reCAPTCHA tokens."""
    
    VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
    
    @staticmethod
    def verify_recaptcha(token: str, remote_ip: str = None) -> Dict[str, Any]:
        """
        Verify a reCAPTCHA token with Google's API.
        
        Args:
            token: The reCAPTCHA token from the frontend
            remote_ip: Optional IP address of the user
            
        Returns:
            Dict containing verification result with keys:
                - success: bool indicating if verification passed
                - challenge_ts: timestamp of the challenge
                - hostname: hostname where verification occurred
                - error-codes: list of error codes if verification failed
                
        Raises:
            Exception: If the verification request fails
        """
        if not hasattr(settings, 'RECAPTCHA_SECRET_KEY') or not settings.RECAPTCHA_SECRET_KEY:
            raise ValueError("RECAPTCHA_SECRET_KEY not configured in settings")
        
        payload = {
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': token
        }
        
        if remote_ip:
            payload['remoteip'] = remote_ip
        
        try:
            response = requests.post(
                RecaptchaService.VERIFY_URL,
                data=payload,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise Exception(f"Failed to verify reCAPTCHA: {str(e)}")
    
    @staticmethod
    def is_valid(token: str, remote_ip: str = None) -> bool:
        """
        Simple boolean check if reCAPTCHA token is valid.
        
        Args:
            token: The reCAPTCHA token from the frontend
            remote_ip: Optional IP address of the user
            
        Returns:
            bool: True if verification passed, False otherwise
        """
        try:
            result = RecaptchaService.verify_recaptcha(token, remote_ip)
            return result.get('success', False)
        except Exception:
            # If verification fails, treat as invalid
            return False
