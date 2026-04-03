"""Email alert channel"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

from ..utils.config import EmailConfig
from .models import Alert

logger = logging.getLogger(__name__)


class EmailAlert:
    def __init__(self, config: EmailConfig):
        self.config = config
        self.enabled = config.enabled
    
    def send(self, alert: Alert) -> bool:
        if not self.enabled:
            logger.debug("Email alerts disabled")
            return False
        
        if not self.config.recipients:
            logger.warning("No email recipients configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self._build_subject(alert)
            msg['From'] = self.config.username
            msg['To'] = ', '.join(self.config.recipients)
            
            text_body = self._build_text_body(alert)
            html_body = self._build_html_body(alert)
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                if self.config.username and self.config.password:
                    server.login(self.config.username, self.config.password)
                server.sendmail(self.config.username, self.config.recipients, msg.as_string())
            
            logger.info(f"Email sent successfully to {len(self.config.recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            raise
    
    def _build_subject(self, alert: Alert) -> str:
        severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
        emoji = severity_emoji.get(alert.severity.name, '⚠️')
        return f"{emoji} Netwatcher Alert: {alert.attack_type}"
    
    def _build_text_body(self, alert: Alert) -> str:
        lines = [
            "NETWATCHER SECURITY ALERT", "=" * 40, "",
            f"Severity: {alert.severity.name}",
            f"Attack Type: {alert.attack_type}",
            f"Confidence: {alert.confidence * 100:.1f}%",
            f"Time: {alert.timestamp}", "",
        ]
        if alert.source_ip:
            lines.append(f"Source IP: {alert.source_ip}")
        if alert.destination_ip:
            lines.append(f"Destination IP: {alert.destination_ip}")
        if alert.ports:
            lines.append(f"Ports: {', '.join(map(str, alert.ports))}")
        lines.append("", "Message:", alert.message)
        if alert.explanation:
            lines.extend(["", "AI Analysis:", alert.explanation])
        if alert.recommendations:
            lines.extend(["", "Recommended Actions:"])
            for i, rec in enumerate(alert.recommendations, 1):
                lines.append(f"  {i}. {rec}")
        lines.extend(["", "-" * 40, "This is an automated alert from Netwatcher."])
        return "\n".join(lines)
    
    def _build_html_body(self, alert: Alert) -> str:
        severity_colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#17a2b8'}
        color = severity_colors.get(alert.severity.name, '#6c757d')
        
        return f"""
        <!DOCTYPE html><html><head><style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .alert-box {{ background-color: #f8f9fa; border-left: 4px solid {color}; padding: 15px; margin: 15px 0; }}
            .label {{ font-weight: bold; color: #555; }}
            .recommendations {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; }}
        </style></head><body>
            <div class="header"><h1>🔔 Netwatcher Security Alert</h1><p>{alert.severity.name} Severity</p></div>
            <div class="content">
                <div class="alert-box">
                    <p><span class="label">Attack Type:</span> {alert.attack_type}</p>
                    <p><span class="label">Confidence:</span> {alert.confidence * 100:.1f}%</p>
                    <p><span class="label">Time:</span> {alert.timestamp}</p>
                    {f'<p><span class="label">Source IP:</span> {alert.source_ip}</p>' if alert.source_ip else ''}
                </div>
                <h3>Details</h3><p>{alert.message}</p>
                {f'<h3>AI Analysis</h3><p>{alert.explanation}</p>' if alert.explanation else ''}
                {f'''<div class="recommendations"><h3>⚡ Recommended Actions</h3><ol>{"".join(f"<li>{r}</li>" for r in alert.recommendations)}</ol></div>''' if alert.recommendations else ''}
            </div>
            <div style="font-size: 12px; color: #777; padding: 20px; text-align: center;">
                <p>Alert ID: {alert.id} | Netwatcher Security Monitor</p>
            </div>
        </body></html>"""
