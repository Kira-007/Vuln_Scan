import sys
import os
import platform
import psutil
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel, QLineEdit
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QColor, QPainter
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from fpdf import FPDF
from MainBackend import scan_service, get_open_ports, scan_ip  # Ensure `scan_ip` is defined
from PySide6.QtWidgets import QProgressBar
class VulnerabilityScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Agentless Vulnerability and Network Scanner")
        self.setGeometry(100, 100, 1000, 600)

        # Set gradient background
        self.setStyleSheet("""
            QMainWindow {
                background: linear-gradient(90deg, rgba(2,0,36,1) 0%, rgba(9,9,121,1) 35%, rgba(0,212,255,1) 100%);
            }
        """)

        # Main layout
        main_layout = QHBoxLayout()
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Sidebar
        sidebar_widget = QWidget()
        self.sidebar_layout = QVBoxLayout()
        sidebar_widget.setLayout(self.sidebar_layout)
        sidebar_widget.setFixedWidth(200)
        sidebar_widget.setStyleSheet("background-color: #36454F; border-radius: 10px;")
        main_layout.addWidget(sidebar_widget)

        # Add buttons to sidebar
        self.scan_button = QPushButton("Scan")
        self.scan_button.setStyleSheet(self.button_style())
        self.scan_button.clicked.connect(self.run_scan)
        self.sidebar_layout.addWidget(self.scan_button)

        self.download_button = QPushButton("Download PDF")
        self.download_button.setStyleSheet(self.button_style())
        self.download_button.clicked.connect(self.download_report_as_pdf)
        self.sidebar_layout.addWidget(self.download_button)
        self.sidebar_layout.addStretch()

        # Content layout
        content_layout = QVBoxLayout()
        main_layout.addLayout(content_layout)

        # Title
        title_label = QLabel("Agentless Vulnerability and Network Scanner")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(title_label)

        # IP input
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address to scan")
        self.ip_input.setStyleSheet("background-color: white; color: black; font-size: 14px;")
        content_layout.addWidget(self.ip_input)

        self.scan_ip_button = QPushButton("Scan Specific IP")
        self.scan_ip_button.setStyleSheet(self.button_style())
        self.scan_ip_button.clicked.connect(self.scan_specific_ip)
        content_layout.addWidget(self.scan_ip_button)

        # Scan result display
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        self.result_display.setStyleSheet("background-color: white; color: black; font-size: 15px;")
        content_layout.addWidget(self.result_display)

        # Pie chart
        self.chart = QChart()
        self.chart.setTitle("Vulnerability Overview")
        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        content_layout.addWidget(self.chart_view)

    def button_style(self):
        """Return stylesheet for sidebar buttons."""
        return """
            QPushButton {
                background-color: #556B7D;
                color: white;
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #6C849A;
            }
            QPushButton:pressed {
                background-color: #3D4E5A;
            }
        """

    def run_scan(self):
        """Perform a scan and update the result display and pie chart."""
        self.result_display.clear()
        self.result_display.append("Running Vulnerability and Network Scan...\n")

        # Combine all scanning results
        service_scan_result = scan_service()
        ports_scan_result = get_open_ports()

        self.result_display.append("Service Scan Results:\n" + service_scan_result)
        self.result_display.append("\nOpen Ports Scan Results:\n" + ports_scan_result)

        vulnerabilities_count = service_scan_result.count("vulnerability") + ports_scan_result.count("open port")
        self.update_pie_chart(vulnerabilities_count)

    def scan_specific_ip(self):
        """Scan a user-specified IP."""
        ip_address = self.ip_input.text().strip()
        if not ip_address:
            self.result_display.setText("Please enter a valid IP address.")
            return

        self.result_display.clear()
        self.result_display.append(f"Scanning IP: {ip_address}\n")
        try:
            result = scan_ip(ip_address)
            self.result_display.append(result)
        except Exception as e:
            self.result_display.append(f"Error scanning IP: {str(e)}")

    def download_report_as_pdf(self):
        """Download the current scan results as a PDF."""
        file_path = os.path.join(os.getcwd(), "scan_report.pdf")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=14)
        pdf.cell(200, 10, txt="Agentless Vulnerability and Network Scanner Report", ln=True, align='C')
        pdf.ln(10)  # Line break

        # Scan Results Title
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(200, 10, txt="Scan Results", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt="The following are the results of the agentless vulnerability and network scan.")
        pdf.ln(5)  # Line break

        # Add scan results content
        scan_result_text = self.result_display.toPlainText()
        for line in scan_result_text.splitlines():
            pdf.multi_cell(0, 10, txt=line)
        
        # Line break
        pdf.ln(10)

        # Pie Chart Data Heading
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(200, 10, txt="Vulnerability Overview", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt="Vulnerability data in the form of pie chart:")
        
        # Final line break
        pdf.ln(10)

        pdf.output(file_path)
        self.result_display.append(f"\nReport saved as {file_path}")


    def update_pie_chart(self, vulnerabilities_count):
        safe_count = 100 - vulnerabilities_count if vulnerabilities_count <= 100 else 0
        vulnerable_count = min(vulnerabilities_count, 100)

        self.chart.removeAllSeries()
        series = QPieSeries()
        series.append("Safe", safe_count)
        series.append("Vulnerable", vulnerable_count)

        series.slices()[0].setBrush(QColor(76, 175, 80))
        series.slices()[1].setBrush(QColor(244, 67, 54))

        self.chart.addSeries(series)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = VulnerabilityScannerApp()
    main_window.show()
    sys.exit(app.exec())
