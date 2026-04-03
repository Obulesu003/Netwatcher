"""SMS alert channel using Twilio"""

import logging
from typing import List

logger = logging.getLogger(__name__)

try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False

from ..utils.config import SMSConfig
from .models import Alert


class SMSAlert:
    def __init__(self, config: SMSConfig):
        self.config = config
        self.enabled = config.enabled
        if self.enabled and TWILIO_AVAILABLE:
            self._client = Client(config.twilio_sid, config.twilio_token)
        else:
            self._client = None
    
    def send(self, alert: Alert) -> bool:
        if not self.enabled:
            logger.debug("SMS alerts disabled")
            return False
        
        if not TWILIO_AVAILABLE:
            logger.warning("Twilio library not installed")
            return False
        
        if not self.config.to_numbers:
            logger.warning("No SMS recipients configured")
            return False
        
        message_body = self._build_message(alert)
        
        try:
            for to_number in self.config.to_numbers:
                self._client.messages.create(
                    body=message_body,
                    from_=self.config.from_number,
                    to=to_number
                )
                logger.info(f"SMS sent to {to_number}")
            return True
        except Exception as e:
            logger.error(f"Failed to send SMS: {e}")
            raise
    
    def _build_message(self, alert: Alert) -> str:
        severity_indicator = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️'}
        indicator = severity_indicator.get(alert.severity.name, '🔔')
        
        message = f"{indicator} Netwatcher: {alert.attack_type} detected ({alert.confidence*100:.0f}% conf)."
        if alert.source_ip:
            message += f" Src: {alert.source_ip}."
        message += " Check dashboard."
        
        return message[:160]
