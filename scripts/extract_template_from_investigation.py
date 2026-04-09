#!/usr/bin/env python3
"""
CLI wrapper around the existing template_promoter.py logic.
Extracts a template from a completed investigation for batch import.

Usage:
    python scripts/extract_template_from_investigation.py --investigation-id <UUID>
    python scripts/extract_template_from_investigation.py --task-id <UUID>
"""
import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

from worker.stages.template_promoter import templatize_code, validate_template_code


def main():
    parser = argparse.ArgumentParser(description='Extract skill template from investigation')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--investigation-id', type=str, help='Investigation UUID')
    group.add_argument('--task-id', type=str, help='Task UUID')
    parser.add_argument('--db-url', type=str,
                        default=os.getenv('DATABASE_URL',
                        'postgresql://zovark:zovark_dev_2026@localhost:5432/zovark'))
    args = parser.parse_args()

    import psycopg2
    conn = psycopg2.connect(args.db_url)
    cursor = conn.cursor()

    # Fetch the investigation data
    if args.investigation_id:
        cursor.execute("""
            SELECT at.task_type, at.generated_code,
                   at.input->'siem_event' as siem_event
            FROM investigations i
            JOIN agent_tasks at ON at.id = i.task_id
            WHERE i.id = %s
        """, (args.investigation_id,))
    else:
        cursor.execute("""
            SELECT task_type, generated_code,
                   input->'siem_event' as siem_event
            FROM agent_tasks WHERE id = %s
        """, (args.task_id,))

    row = cursor.fetchone()
    if not row:
        print(json.dumps({"error": "Investigation not found"}), file=sys.stderr)
        sys.exit(1)

    task_type, generated_code, siem_event = row

    if not generated_code:
        print(json.dumps({"error": "No generated code found (likely Path A template)"}), file=sys.stderr)
        sys.exit(1)

    # Parse siem_event
    if isinstance(siem_event, str):
        siem_dict = json.loads(siem_event)
    elif isinstance(siem_event, dict):
        siem_dict = siem_event
    else:
        siem_dict = {}

    # Use existing templatization logic
    template_code = templatize_code(generated_code, siem_dict)

    # Validate
    is_valid, error = validate_template_code(template_code)

    result = {
        "task_type": task_type,
        "code_template": template_code,
        "valid": is_valid,
        "validation_error": error if not is_valid else None,
        "threat_types": [task_type],
        "auto_promoted": True,
        "source": "cli_extraction",
    }

    print(json.dumps(result, indent=2))
    conn.close()


if __name__ == "__main__":
    main()
