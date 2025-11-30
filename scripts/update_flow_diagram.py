"""
Skrypt do automatycznej aktualizacji diagramu flow na podstawie aktualnej struktury aplikacji.
Analizuje collectory, procesory i moduły, a następnie aktualizuje diagram PlantUML.
"""
import json
import re
from pathlib import Path
from typing import List, Dict

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"
COLLECTOR_REGISTRY_PATH = PROJECT_ROOT / "core" / "collector_registry.py"
PROCESSOR_REGISTRY_PATH = PROJECT_ROOT / "core" / "processor_registry.py"
DIAGRAM_PATH = PROJECT_ROOT / "docs" / "MVP_PIPELINE_FLOW.puml"


def get_collectors_from_config() -> List[str]:
    """Pobiera listę collectorów z config.json."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
            return config.get("collectors", {}).get("enabled", [])
    except Exception as e:
        print(f"Error reading config: {e}")
        return []


def get_collectors_from_registry() -> List[Dict[str, str]]:
    """Pobiera listę collectorów z collector_registry.py."""
    collectors = []
    try:
        with open(COLLECTOR_REGISTRY_PATH, "r", encoding="utf-8") as f:
            content = f.read()
            # Znajdź wszystkie registry.register() calls
            pattern = r'registry\.register\("([^"]+)",\s*([^,]+),\s*"([^"]*)"'
            matches = re.findall(pattern, content)
            for match in matches:
                name, func, description = match
                collectors.append({
                    "name": name,
                    "description": description or name
                })
    except Exception as e:
        print(f"Error reading collector registry: {e}")
    return collectors


def get_processors_from_registry() -> List[Dict[str, str]]:
    """Pobiera listę procesorów z processor_registry.py."""
    processors = []
    try:
        with open(PROCESSOR_REGISTRY_PATH, "r", encoding="utf-8") as f:
            content = f.read()
            # Znajdź wszystkie registry.register() calls
            pattern = r'registry\.register\("([^"]+)",\s*([^,]+),\s*"([^"]*)"'
            matches = re.findall(pattern, content)
            for match in matches:
                name, func, description = match
                processors.append({
                    "name": name,
                    "description": description or name
                })
    except Exception as e:
        print(f"Error reading processor registry: {e}")
    return processors


def generate_collector_rectangles(collectors: List[Dict[str, str]]) -> str:
    """Generuje definicje prostokątów dla collectorów."""
    lines = []
    for collector in collectors:
        name = collector["name"]
        description = collector.get("description", name)
        # Krótka wersja opisu dla diagramu
        short_desc = description.split(" - ")[0] if " - " in description else description
        lines.append(f'rectangle "Collector: {name.title()}\\n{short_desc}" <<Collector>> {{')
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def generate_collector_connections(collectors: List[Dict[str, str]]) -> str:
    """Generuje połączenia dla collectorów."""
    lines = []
    for collector in collectors:
        name = collector["name"]
        title_name = name.title().replace("_", " ")
        lines.append(f'"Collector Master (Async)" --> "Collector: {title_name}" : Async request (parallel)')
    lines.append("")
    for collector in collectors:
        name = collector["name"]
        title_name = name.title().replace("_", " ")
        lines.append(f'"Collector: {title_name}" --> "Collector Master (Async)" : JSON + status')
    return "\n".join(lines)


def generate_logger_connections(collectors: List[Dict[str, str]]) -> str:
    """Generuje połączenia do Logger."""
    lines = []
    for collector in collectors:
        name = collector["name"]
        title_name = name.title().replace("_", " ")
        lines.append(f'"Collector: {title_name}" --> Logger')
    return "\n".join(lines)


def update_diagram():
    """Aktualizuje diagram PlantUML na podstawie aktualnej struktury."""
    print("🔄 Updating flow diagram...")
    
    # Pobierz dane
    collectors = get_collectors_from_registry()
    if not collectors:
        # Fallback do config
        collector_names = get_collectors_from_config()
        collectors = [{"name": name, "description": name} for name in collector_names]
    
    print(f"📊 Found {len(collectors)} collectors")
    
    # Generuj nowe sekcje diagramu
    collector_rectangles = generate_collector_rectangles(collectors)
    collector_connections = generate_collector_connections(collectors)
    logger_connections = generate_logger_connections(collectors)
    
    # Wczytaj obecny diagram
    try:
        with open(DIAGRAM_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Error reading diagram: {e}")
        return False
    
    # Znajdź sekcję z collectorami (między "' Collectors Layer" a "' Flow Connections")
    pattern = r"(' Collectors Layer.*?)(\n' Flow Connections)"
    replacement = f"' Collectors Layer (Async)\n{collector_rectangles}\n' Flow Connections"
    
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    # Zaktualizuj połączenia collectorów
    pattern = r'("Collector Master \(Async\)" --> "Collector:.*?\n)+'
    new_content = re.sub(pattern, collector_connections + "\n", new_content)
    
    pattern = r'("Collector:.*?" --> "Collector Master \(Async\)".*?\n)+'
    new_content = re.sub(pattern, collector_connections.split("\n\n")[1] + "\n\n", new_content)
    
    # Zaktualizuj połączenia do Logger
    pattern = r'("Collector:.*?" --> Logger\n)+'
    new_content = re.sub(pattern, logger_connections + "\n", new_content)
    
    # Zapisz zaktualizowany diagram
    try:
        with open(DIAGRAM_PATH, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"✅ Diagram updated: {DIAGRAM_PATH}")
        return True
    except Exception as e:
        print(f"❌ Error writing diagram: {e}")
        return False


if __name__ == "__main__":
    success = update_diagram()
    if success:
        print("\n💡 Tip: Run this script after adding/removing collectors to keep the diagram up to date.")
    else:
        print("\n⚠️  Diagram update failed. Please check the errors above.")

