"""
Recommendation Engine - dobiera zalecenia na podstawie wykrytych problemów.
"""

# Mapowanie typów problemów na rekomendacje
RECOMMENDATIONS = {
    "REGISTRY_TXR_FAILURE": [
        {
            "priority": "CRITICAL",
            "action": "Run chkdsk /f /r",
            "description": "Check and repair disk errors - TxR failures indicate possible disk corruption"
        },
        {
            "priority": "CRITICAL",
            "action": "Run DISM /RestoreHealth",
            "description": "Restore Windows image health"
        },
        {
            "priority": "HIGH",
            "action": "Run sfc /scannow",
            "description": "Scan and repair system file corruption"
        },
        {
            "priority": "HIGH",
            "action": "Verify Volume Shadow Copy health",
            "description": "Check VSS service and shadow copy integrity"
        }
    ],
    "SMART_ERROR": [
        {
            "priority": "CRITICAL",
            "action": "Run SMART long test",
            "description": "Perform comprehensive disk health check"
        },
        {
            "priority": "HIGH",
            "action": "Backup data immediately",
            "description": "SMART errors indicate physical disk failure - backup critical data"
        },
        {
            "priority": "HIGH",
            "action": "Check storage controller drivers",
            "description": "Update or reinstall storage controller drivers"
        },
        {
            "priority": "MEDIUM",
            "action": "Check SATA/NVMe cabling or slot",
            "description": "Verify physical connections"
        }
    ],
    "DISK_ERROR": [
        {
            "priority": "HIGH",
            "action": "Run chkdsk /f",
            "description": "Check and repair file system errors"
        },
        {
            "priority": "HIGH",
            "action": "Run SMART long test",
            "description": "Check disk physical health"
        },
        {
            "priority": "MEDIUM",
            "action": "Check storage controller drivers",
            "description": "Update storage drivers"
        },
        {
            "priority": "MEDIUM",
            "action": "Check SATA/NVMe cabling or slot",
            "description": "Verify physical connections"
        }
    ],
    "IO_ERROR": [
        {
            "priority": "HIGH",
            "action": "Check storage controller drivers",
            "description": "Update or reinstall storage controller drivers"
        },
        {
            "priority": "MEDIUM",
            "action": "Check SATA/NVMe cabling or slot",
            "description": "Verify physical connections"
        },
        {
            "priority": "MEDIUM",
            "action": "Run chkdsk /f",
            "description": "Check file system integrity"
        }
    ],
    "DRIVER_LOAD_FAILURE": [
        {
            "priority": "HIGH",
            "action": "Update or reinstall problematic drivers",
            "description": "Driver failed to load - check Device Manager for errors"
        },
        {
            "priority": "MEDIUM",
            "action": "Run sfc /scannow",
            "description": "Check for system file corruption"
        }
    ],
    "GPU_DRIVER_CRASH": [
        {
            "priority": "HIGH",
            "action": "Clean reinstall GPU drivers",
            "description": "Uninstall current drivers and install latest version"
        },
        {
            "priority": "MEDIUM",
            "action": "Check thermals",
            "description": "Monitor GPU temperature and cooling"
        },
        {
            "priority": "MEDIUM",
            "action": "Check GPU power supply",
            "description": "Verify adequate power delivery"
        }
    ],
    "NETWORK_ERROR": [
        {
            "priority": "MEDIUM",
            "action": "Flush DNS",
            "description": "Run: ipconfig /flushdns"
        },
        {
            "priority": "MEDIUM",
            "action": "Reset Winsock",
            "description": "Run: netsh winsock reset"
        },
        {
            "priority": "LOW",
            "action": "Disable problematic adapters",
            "description": "Temporarily disable network adapters to isolate issues"
        }
    ],
    "SYSTEM_CRASH": [
        {
            "priority": "CRITICAL",
            "action": "Check minidump files",
            "description": "Analyze crash dumps in C:\\Windows\\Minidump"
        },
        {
            "priority": "HIGH",
            "action": "Update all drivers",
            "description": "Outdated drivers are common cause of crashes"
        },
        {
            "priority": "MEDIUM",
            "action": "Run memory diagnostic",
            "description": "Check for RAM issues with Windows Memory Diagnostic"
        }
    ],
    "CPU_HIGH_TEMP": [
        {
            "priority": "HIGH",
            "action": "Check CPU cooling and clean dust",
            "description": "Clean CPU cooler and verify thermal paste"
        },
        {
            "priority": "MEDIUM",
            "action": "Check case airflow",
            "description": "Ensure proper case ventilation"
        }
    ],
    "RAM_HIGH_USAGE": [
        {
            "priority": "MEDIUM",
            "action": "Identify memory leaks",
            "description": "Use Task Manager to find processes consuming excessive memory"
        },
        {
            "priority": "LOW",
            "action": "Consider adding more RAM",
            "description": "If usage is consistently high, consider hardware upgrade"
        }
    ],
    # Ogólne rekomendacje dla ERROR issues
    "LOGS_COLLECTION_ERROR": [
        {
            "priority": "MEDIUM",
            "action": "Run as administrator",
            "description": "Event logs require administrator privileges"
        }
    ],
    "DRIVER_FAILED": [
        {
            "priority": "HIGH",
            "action": "Update or reinstall problematic drivers",
            "description": "Check Device Manager for driver errors"
        },
        {
            "priority": "MEDIUM",
            "action": "Run sfc /scannow",
            "description": "Check for system file corruption"
        }
    ],
    "SERVICE_FAILURE": [
        {
            "priority": "MEDIUM",
            "action": "Check service status in Services.msc",
            "description": "Review failed services and their dependencies"
        },
        {
            "priority": "LOW",
            "action": "Restart problematic services",
            "description": "Try restarting failed services manually"
        }
    ],
    "SYSTEM_WARNING": [
        {
            "priority": "LOW",
            "action": "Monitor system for recurring warnings",
            "description": "Keep track of warning patterns"
        }
    ]
}


def generate_recommendations(processed_data):
    """
    Generuje rekomendacje na podstawie wykrytych problemów.

    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów

    Returns:
        list: Lista rekomendacji posortowanych według priorytetu
    """
    detected_issue_types = set()

    # Zbierz wszystkie typy problemów
    for _, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            # Critical issues
            critical = processor_data.get("critical_issues", [])
            for issue in critical:
                issue_type = issue.get("type", "")
                if issue_type:
                    detected_issue_types.add(issue_type)

            # Critical events
            critical_events = processor_data.get("critical_events", [])
            for event in critical_events:
                issue_type = event.get("type", "")
                if issue_type:
                    detected_issue_types.add(issue_type)

            # Issues (wszystkie - critical, error, warning)
            issues = processor_data.get("issues", [])
            for issue in issues:
                issue_type = issue.get("type", "")
                if issue_type:
                    detected_issue_types.add(issue_type)

            # Warnings też mogą mieć rekomendacje
            warnings = processor_data.get("warnings", [])
            for warning in warnings:
                issue_type = warning.get("type", "")
                if issue_type:
                    detected_issue_types.add(issue_type)

    # Zbierz rekomendacje dla wykrytych typów problemów
    all_recommendations = []
    seen_actions = set()

    for issue_type in detected_issue_types:
        if issue_type in RECOMMENDATIONS:
            for rec in RECOMMENDATIONS[issue_type]:
                # Unikalność po action
                action_key = rec["action"]
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    all_recommendations.append(rec)

    # Sortuj według priorytetu
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_recommendations.sort(
        key=lambda x: priority_order.get(x.get("priority", "LOW"), 3)
    )

    return all_recommendations[:15]  # Max 15 rekomendacji