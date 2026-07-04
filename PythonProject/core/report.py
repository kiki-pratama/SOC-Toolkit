from datetime import datetime
from typing import Any

import pandas as pd
from fpdf import FPDF


def safe_pdf_text(value: Any) -> str:
    return str(value).encode("latin-1", "replace").decode("latin-1")


def trim_text(value: Any, limit: int) -> str:
    text = safe_pdf_text(value)

    if len(text) > limit:
        return text[: limit - 2] + ".."

    return text


class IncidentPDF(FPDF):
    def header(self) -> None:
        self.set_font("Arial", "B", 15)
        self.cell(0, 10, "SOC Incident Report", 0, 1, "C")

        self.set_font("Arial", "I", 9)
        self.cell(
            0,
            8,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            0,
            1,
            "C",
        )

        self.ln(4)

    def section_title(self, title: str) -> None:
        self.set_font("Arial", "B", 12)
        self.set_fill_color(220, 230, 245)
        self.cell(0, 9, safe_pdf_text(title), 0, 1, "L", True)
        self.ln(3)

    def section_body(self, body: str) -> None:
        self.set_font("Arial", "", 10)
        self.multi_cell(0, 7, safe_pdf_text(body))
        self.ln(4)


def write_table_header(pdf: IncidentPDF) -> None:
    headers = [
        ("IP", 35),
        ("Score", 18),
        ("Category", 25),
        ("Severity", 22),
        ("Reports", 18),
        ("Country", 18),
        ("ISP", 55),
        ("Action", 75),
    ]

    pdf.set_font("Arial", "B", 8)
    pdf.set_fill_color(235, 235, 235)

    for title, width in headers:
        pdf.cell(width, 8, title, 1, 0, "C", True)

    pdf.ln()


def create_pdf_report(
    df: pd.DataFrame,
    malicious_count: int,
    suspicious_count: int,
    clean_count: int,
    error_count: int,
) -> bytes:
    pdf = IncidentPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    summary = (
        f"Total Items: {len(df)}\n"
        f"Malicious: {malicious_count}\n"
        f"Suspicious: {suspicious_count}\n"
        f"Clean: {clean_count}\n"
        f"Invalid/Error: {error_count}"
    )

    pdf.section_title("Executive Summary")
    pdf.section_body(summary)

    pdf.section_title("Investigation Log")
    write_table_header(pdf)

    pdf.set_font("Arial", "", 7)

    for _, row in df.iterrows():
        if pdf.get_y() > 185:
            pdf.add_page()
            write_table_header(pdf)
            pdf.set_font("Arial", "", 7)

        pdf.cell(35, 8, trim_text(row.get("IP", "-"), 25), 1)
        pdf.cell(18, 8, trim_text(row.get("Risk Score", "-"), 8), 1, 0, "C")
        pdf.cell(25, 8, trim_text(row.get("Category", "-"), 18), 1, 0, "C")
        pdf.cell(22, 8, trim_text(row.get("Severity", "-"), 18), 1, 0, "C")
        pdf.cell(18, 8, trim_text(row.get("Reports", 0), 8), 1, 0, "C")
        pdf.cell(18, 8, trim_text(row.get("Country", "-"), 8), 1, 0, "C")
        pdf.cell(55, 8, trim_text(row.get("ISP", "-"), 38), 1)
        pdf.cell(75, 8, trim_text(row.get("Recommended Action", "-"), 55), 1)
        pdf.ln()

    output = pdf.output(dest="S")

    if isinstance(output, str):
        return output.encode("latin-1", "replace")

    return bytes(output)
