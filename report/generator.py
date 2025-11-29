import json
import os
from zipfile import ZipFile

def generate_report(results):
    os.makedirs('reports', exist_ok=True)
    json_path = os.path.join('reports', 'scan_results.json')
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=4)

    zip_path = os.path.join('reports', 'scan_report.zip')
    with ZipFile(zip_path, 'w') as zipf:
        zipf.write(json_path)
    print(f"Report saved: {zip_path}")
