import json
import os

CASES_FILE = os.path.join('learning', 'cases.json')

def update_cases(results):
    os.makedirs('learning', exist_ok=True)
    if os.path.exists(CASES_FILE):
        with open(CASES_FILE, 'r') as f:
            cases = json.load(f)
    else:
        cases = []

    cases.append(results)

    with open(CASES_FILE, 'w') as f:
        json.dump(cases, f, indent=4)
