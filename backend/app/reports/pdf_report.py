"""
Institutional PDF Security Assessment Report Generator for OMEGA Platform.
Generates audit-grade PDF documents using ReportLab.
"""

import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.core.config import settings

def generate_pdf_report(
    capture_data: dict[str, Any],
    tunnels_data: list[dict[str, Any]],
    findings_data: list[dict[str, Any]],
    risk_data: dict[str, Any],
    output_path: Path
) -> str:
    """
    Generates an institutional PDF assessment report.
    """
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F2544")
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )

    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0F2544"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1E293B")
    )

    mono_style = ParagraphStyle(
        'Mono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    elements = []

    # Header section
    elements.append(Paragraph("OMEGA // SOVEREIGN IPSEC SECURITY ASSESSMENT", title_style))
    elements.append(Paragraph("Sovereign IPsec Security Intelligence & Assessment Platform | SIH26160", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F2544"), spaceAfter=12))

    # Metadata summary table
    meta_table_data = [
        [
            Paragraph("<b>Target Capture:</b>", body_style),
            Paragraph(capture_data.get("filename", "capture.pcap"), body_style),
            Paragraph("<b>Analysis Engine:</b>", body_style),
            Paragraph(f"{settings.VERSION} (AIR-GAPPED)", body_style)
        ],
        [
            Paragraph("<b>SHA-256 Hash:</b>", body_style),
            Paragraph(f"<font size='7'>{capture_data.get('sha256', 'N/A')}</font>", body_style),
            Paragraph("<b>Rule Pack:</b>", body_style),
            Paragraph(settings.RULEPACK_VERSION, body_style)
        ],
        [
            Paragraph("<b>Assessment Time:</b>", body_style),
            Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style),
            Paragraph("<b>Overall Risk Posture:</b>", body_style),
            Paragraph(f"<b>{risk_data.get('overall_score', 0.0)} / 100 ({risk_data.get('risk_level', 'LOW')})</b>", body_style)
        ]
    ]

    meta_table = Table(meta_table_data, colWidths=[90, 180, 100, 170])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # Executive Summary
    elements.append(Paragraph("1. Executive Summary & Posture Breakdown", h1_style))
    summary_text = (
        f"Passive cryptographic assessment was conducted on network capture '{capture_data.get('filename')}' "
        f"comprising {capture_data.get('packet_count', 0)} total packets ({capture_data.get('ike_packet_count', 0)} IKE, "
        f"{capture_data.get('esp_packet_count', 0)} ESP, {capture_data.get('natt_packet_count', 0)} NAT-T). "
        f"A total of {len(tunnels_data)} IPsec tunnel(s) and {len(findings_data)} security finding(s) were identified. "
        f"All analysis is strictly deterministic and metadata-driven without payload decryption."
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 8))

    # Risk Categories Table
    risk_rows = [
        [
            Paragraph("<b>Category</b>", body_style),
            Paragraph("<b>Score (0-100)</b>", body_style),
            Paragraph("<b>Weight</b>", body_style),
            Paragraph("<b>Weighted Impact</b>", body_style)
        ],
        [Paragraph("Crypto Posture (C)", body_style), Paragraph(str(risk_data.get("crypto_score", 0.0)), body_style), Paragraph("35%", body_style), Paragraph(f"{risk_data.get('crypto_score', 0.0) * 0.35:.1f}", body_style)],
        [Paragraph("Key Management (K)", body_style), Paragraph(str(risk_data.get("key_mgmt_score", 0.0)), body_style), Paragraph("25%", body_style), Paragraph(f"{risk_data.get('key_mgmt_score', 0.0) * 0.25:.1f}", body_style)],
        [Paragraph("Protocol Compliance (P)", body_style), Paragraph(str(risk_data.get("protocol_score", 0.0)), body_style), Paragraph("20%", body_style), Paragraph(f"{risk_data.get('protocol_score', 0.0) * 0.20:.1f}", body_style)],
        [Paragraph("Statistical Anomaly (A)", body_style), Paragraph(str(risk_data.get("anomaly_score", 0.0)), body_style), Paragraph("10%", body_style), Paragraph(f"{risk_data.get('anomaly_score', 0.0) * 0.10:.1f}", body_style)],
        [Paragraph("Metadata Exposure (M)", body_style), Paragraph(str(risk_data.get("metadata_score", 0.0)), body_style), Paragraph("10%", body_style), Paragraph(f"{risk_data.get('metadata_score', 0.0) * 0.10:.1f}", body_style)],
    ]
    risk_table = Table(risk_rows, colWidths=[160, 110, 110, 160])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0F2544")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 14))

    # Security Findings Section
    elements.append(Paragraph("2. Technical Security Findings & Recommendations", h1_style))
    if findings_data:
        finding_rows = [
            [
                Paragraph("<b>ID</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Title & Standards Reference</b>", body_style),
                Paragraph("<b>Evidence Type</b>", body_style)
            ]
        ]
        for f in findings_data[:15]:
            sev_color = "#DC2626" if f.get("severity") in ("CRITICAL", "HIGH") else ("#D97706" if f.get("severity") == "MEDIUM" else "#2563EB")
            finding_rows.append([
                Paragraph(f.get("rule_id", "N/A"), mono_style),
                Paragraph(f"<font color='{sev_color}'><b>{f.get('severity')}</b></font>", body_style),
                Paragraph(f"<b>{f.get('title')}</b><br/><font color='#64748B'>{f.get('standards_reference')}</font>", body_style),
                Paragraph(f.get("evidence_type", "OBSERVED"), body_style),
            ])
        findings_table = Table(finding_rows, colWidths=[90, 70, 300, 80])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0F2544")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(findings_table)
    else:
        elements.append(Paragraph("No non-compliant findings detected in capture.", body_style))

    elements.append(Spacer(1, 14))

    # Strict Visibility Boundaries Statement
    elements.append(Paragraph("3. Sovereign Visibility Model & Epistemic Boundaries", h1_style))
    boundary_text = (
        "<b>OBSERVED:</b> IKE handshakes, proposals, transform attributes, ESP SPIs, and sequence numbers (100% confidence).<br/>"
        "<b>DERIVED:</b> Rekey intervals, sequence gaps, and packet rates computed deterministically from frames.<br/>"
        "<b>INFERRED:</b> Flow dynamics and statistical anomalies with explicitly declared confidence percentages.<br/>"
        "<b>UNOBSERVABLE:</b> Inner plaintext payloads, encapsulated private IP headers, pre-shared keys (PSK), and private keys "
        "remain completely protected by cryptography and are not reconstructed."
    )
    elements.append(Paragraph(boundary_text, body_style))

    doc.build(elements)

    # Compute hash of generated PDF
    sha256 = ""
    with open(output_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    return sha256
