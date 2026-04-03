#!/usr/bin/env python3
"""Export captured traffic and reports"""

import sys
import os
import csv
import argparse
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.logger import setup_logger
from src.utils.config import get_config

logger = setup_logger("netwatcher.export")


def export_to_csv(packets: list, output_path: str) -> bool:
    """Export packets to CSV format"""
    try:
        if not packets:
            logger.warning("No packets to export")
            return False
        
        with open(output_path, 'w', newline='') as f:
            if packets:
                writer = csv.DictWriter(f, fieldnames=packets[0].keys())
                writer.writeheader()
                writer.writerows(packets)
        
        logger.info(f"Exported {len(packets)} packets to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"CSV export failed: {e}")
        return False


def export_to_pdf(
    stats: dict,
    classification: dict,
    explanation: dict,
    output_path: str
) -> bool:
    """Export analysis report to PDF format"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        story.append(Paragraph("Netwatcher Traffic Analysis Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Traffic Statistics", styles['Heading2']))
        stats_data = [
            ["Metric", "Value"],
            ["Total Packets", str(stats.get('total_packets', 0))],
            ["Total Bytes", f"{stats.get('total_bytes', 0):,}"],
            ["Duration", f"{stats.get('duration', 0):.2f}s"],
            ["Packets/sec", f"{stats.get('packets_per_second', 0):.2f}"],
            ["Unique Source IPs", str(stats.get('unique_src_ips', 0))],
            ["Unique Dest IPs", str(stats.get('unique_dst_ips', 0))],
        ]
        stats_table = Table(stats_data, colWidths=[2.5*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        if classification:
            story.append(Paragraph("Classification Results", styles['Heading2']))
            cls_data = [
                ["Field", "Value"],
                ["Category", classification.get('category', 'Unknown')],
                ["Label", classification.get('label', 'Unknown')],
                ["Confidence", f"{classification.get('confidence', 0) * 100:.1f}%"],
                ["Threat Level", classification.get('threat_level', 'none').upper()],
            ]
            cls_table = Table(cls_data, colWidths=[2.5*inch, 2.5*inch])
            cls_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cls_table)
            story.append(Spacer(1, 20))
        
        if explanation:
            story.append(Paragraph("AI Analysis", styles['Heading2']))
            if explanation.get('summary'):
                story.append(Paragraph(f"<b>Summary:</b> {explanation['summary']}", styles['Normal']))
                story.append(Spacer(1, 10))
            
            if explanation.get('ai_explanation'):
                story.append(Paragraph(f"<b>Analysis:</b> {explanation['ai_explanation']}", styles['Normal']))
                story.append(Spacer(1, 10))
            
            if explanation.get('recommendations'):
                story.append(Paragraph("<b>Recommendations:</b>", styles['Normal']))
                for rec in explanation['recommendations']:
                    story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        doc.build(story)
        logger.info(f"PDF report saved to {output_path}")
        return True
        
    except ImportError:
        logger.error("reportlab not installed. Install with: pip install reportlab")
        return False
    except Exception as e:
        logger.error(f"PDF export failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Export Netwatcher data and reports")
    parser.add_argument('--input', '-i', help='Input JSON file')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['csv', 'pdf', 'json'], default='csv')
    
    args = parser.parse_args()
    
    config = get_config("config.yaml")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    sample_stats = {
        'total_packets': 1000,
        'total_bytes': 500000,
        'duration': 60.0,
        'packets_per_second': 16.67,
        'unique_src_ips': 5,
        'unique_dst_ips': 10
    }
    
    sample_classification = {
        'category': 'Normal',
        'label': 'BENIGN',
        'confidence': 0.95,
        'threat_level': 'none'
    }
    
    sample_explanation = {
        'summary': 'Normal network traffic detected with typical patterns.',
        'ai_explanation': 'Traffic shows normal web browsing activity.',
        'recommendations': ['Continue monitoring', 'Review access logs periodically']
    }
    
    output_path = f"./data/reports/sample_report_{timestamp}.pdf"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    logger.info("Generating sample report...")
    success = export_to_pdf(sample_stats, sample_classification, sample_explanation, output_path)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
