"""Slack alert channel"""

import json
import requests
import logging

from ..utils.config import SlackConfig
from .models import Alert

logger = logging.getLogger(__name__)


class SlackAlert:
    def __init__(self, config: SlackConfig):
        self.config = config
        self.enabled = config.enabled
        self.webhook_url = config.webhook_url
    
    def send(self, alert: Alert) -> bool:
        if not self.enabled:
            logger.debug("Slack alerts disabled")
            return False
        
        if not self.webhook_url:
            logger.warning("No Slack webhook URL configured")
            return False
        
        payload = self._build_payload(alert)
        
        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.error(f"Slack webhook error: {response.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"Failed to send Slack alert: {e}")
            raise
    
    def _build_payload(self, alert: Alert) -> dict:
        severity_colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#17a2b8'}
        color = severity_colors.get(alert.severity.name, '#6c757d')
        
        fields = [
            {"title": "Attack Type", "value": alert.attack_type, "short": True},
            {"title": "Confidence", "value": f"{alert.confidence * 100:.1f}%", "short": True},
            {"title": "Severity", "value": alert.severity.name, "short": True},
            {"title": "Time", "value": alert.timestamp.split('T')[1][:8], "short": True}
        ]
        if alert.source_ip:
            fields.append({"title": "Source IP", "value": alert.source_ip, "short": True})
        
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {alert.attack_type} Detected", "emoji": True}},
            {"type": "section", "fields": fields}
        ]
        
        if alert.explanation:
            text = alert.explanation[:200] + ('...' if len(alert.explanation) > 200 else '')
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{text}*"}})
        
        if alert.recommendations:
            rec_text = "\n".join(f"• {rec}" for rec in alert.recommendations[:3])
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Recommended Actions:*\n{rec_text}"}})
        
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Alert ID: `{alert.id}` | Netwatcher"}]})
        
        return {"attachments": [{"color": color, "blocks": blocks}]}
