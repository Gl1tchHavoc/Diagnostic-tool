"""
Wspólne narzędzia eksportu dla GUI i CLI.
Ujednolica format eksportu JSON/HTML.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from utils.logger import get_logger

logger = get_logger()


def export_json(data: Dict[str, Any], filename: Optional[str] = None,
                output_dir: str = "output/processed") -> Path:
    """
    Eksportuje dane do pliku JSON w ujednoliconym formacie.

    Args:
        data: Dane do eksportu (collected_data, processed_data, lub oba)
        filename: Nazwa pliku (opcjonalnie, wygeneruje automatycznie)
        output_dir: Katalog wyjściowy

    Returns:
        Path: Ścieżka do wyeksportowanego pliku
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not filename:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"diagnostic_report_{timestamp_str}.json"

    filepath = output_path / filename

    try:
        # Ujednolicony format eksportu
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "export_version": "1.0",
            "data": data
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                export_data,
                f,
                indent=2,
                ensure_ascii=False,
                default=str)

        logger.info(f"[EXPORT] JSON report exported to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"[EXPORT] Failed to export JSON: {e}")
        raise


def export_html(collected_data: Dict[str, Any], processed_data: Optional[Dict[str, Any]] = None,
                filename: Optional[str] = None, output_dir: str = "output/processed") -> Path:
    """
    Eksportuje dane do pliku HTML w ujednoliconym formacie.

    Args:
        collected_data: Zebrane dane z collectorów
        processed_data: Przetworzone dane (opcjonalnie)
        filename: Nazwa pliku (opcjonalnie, wygeneruje automatycznie)
        output_dir: Katalog wyjściowy

    Returns:
        Path: Ścieżka do wyeksportowanego pliku
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not filename:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"diagnostic_report_{timestamp_str}.html"

    filepath = output_path / filename

    try:
        html_content = generate_html_report(collected_data, processed_data)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"[EXPORT] HTML report exported to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"[EXPORT] Failed to export HTML: {e}")
        raise


def generate_html_report(collected_data: Dict[str, Any],
                         processed_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Generuje raport HTML w ujednoliconym formacie.

    Args:
        collected_data: Zebrane dane z collectorów
        processed_data: Przetworzone dane (opcjonalnie)

    Returns:
        str: Zawartość HTML
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Podsumowanie collectorów
    collectors_summary = ""
    if collected_data:
        collectors = collected_data.get("collectors", {})
        summary = collected_data.get("summary", {})

        collectors_summary = f"""
        <h2>Collectors Summary</h2>
        <div class="summary-stats">
            <div class="stat">
                <span class="stat-label">Total Collectors:</span>
                <span class="stat-value">{summary.get('total_collectors', 0)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Collected:</span>
                <span class="stat-value success">{summary.get('collected', 0)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Errors:</span>
                <span class="stat-value error">{summary.get('errors', 0)}</span>
            </div>
        </div>
        <table class="collectors-table">
            <thead>
                <tr>
                    <th>Collector</th>
                    <th>Status</th>
                    <th>Execution Time</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
        """

        for name, result in collectors.items():
            if isinstance(result, dict):
                status = result.get("status", "Unknown")
                error = result.get("error", "")
                exec_time = result.get("execution_time_ms", 0)
                status_icon = "✅" if status == "Collected" else "❌"
                status_class = "status-collected" if status == "Collected" else "status-error"

                collectors_summary += f"""
                <tr>
                    <td><strong>{name}</strong></td>
                    <td class="{status_class}">{status_icon} {status}</td>
                    <td>{exec_time} ms</td>
                    <td>{error if error else "-"}</td>
                </tr>
                """

        collectors_summary += """
            </tbody>
        </table>
        """

    # Sekcja z przetworzonymi danymi (jeśli dostępne)
    processed_section = ""
    if processed_data:
        processed_section = """
        <h2>Processed Data</h2>
        <div class="processed-data">
            <pre class="json-data">{}</pre>
        </div>
        """.format(json.dumps(processed_data, indent=2, ensure_ascii=False, default=str))

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnostic Tool Report - {timestamp}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1e1e1e;
            color: #ffffff;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #2e2e2e;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}

        h1 {{
            color: #00cc66;
            margin-bottom: 10px;
            font-size: 2em;
        }}

        .timestamp {{
            color: #888;
            margin-bottom: 30px;
            font-size: 0.9em;
        }}

        h2 {{
            color: #0066cc;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #444;
        }}

        .summary-stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .stat {{
            background: #333;
            padding: 15px 20px;
            border-radius: 5px;
            flex: 1;
            min-width: 150px;
        }}

        .stat-label {{
            display: block;
            color: #aaa;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}

        .stat-value {{
            display: block;
            font-size: 1.5em;
            font-weight: bold;
            color: #fff;
        }}

        .stat-value.success {{
            color: #00cc66;
        }}

        .stat-value.error {{
            color: #cc0000;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #2e2e2e;
        }}

        th, td {{
            border: 1px solid #555;
            padding: 12px;
            text-align: left;
        }}

        th {{
            background: #444;
            color: #fff;
            font-weight: bold;
        }}

        tr:nth-child(even) {{
            background: #333;
        }}

        tr:hover {{
            background: #3a3a3a;
        }}

        .status-collected {{
            color: #00cc66;
            font-weight: bold;
        }}

        .status-error {{
            color: #cc0000;
            font-weight: bold;
        }}

        .json-data {{
            background: #1e1e1e;
            padding: 20px;
            border: 1px solid #555;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            line-height: 1.4;
        }}

        .processed-data {{
            margin-top: 20px;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .container {{
                background: white;
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Diagnostic Tool Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>

        {collectors_summary}

        {processed_section}

        <h2>Raw Data (JSON)</h2>
        <div class="json-data">
            {json.dumps(collected_data, indent=2, ensure_ascii=False, default=str)}
        </div>
    </div>
</body>
</html>
    """
    return html
