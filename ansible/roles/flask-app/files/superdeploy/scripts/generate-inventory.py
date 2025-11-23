#!/usr/bin/env python3
"""
Generate Ansible Inventory from Terraform Outputs
Reads terraform-outputs.json and creates Ansible inventory file
"""

import json
import yaml
import sys
from pathlib import Path

def load_terraform_outputs(filepath):
    """Load Terraform outputs from JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filepath} not found")
        print("Run Terraform first to generate outputs")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        sys.exit(1)

def generate_inventory(tf_outputs):
    """Generate Ansible inventory structure from Terraform outputs"""

    inventory = {
        'all': {
            'children': {
                'app_servers': {
                    'hosts': {},
                    'vars': {
                        'ansible_user': 'ubuntu',
                        'ansible_python_interpreter': '/usr/bin/python3'
                    }
                },
                'db_servers': {
                    'hosts': {},
                    'vars': {}
                },
                'cache_servers': {
                    'hosts': {},
                    'vars': {}
                }
            },
            'vars': {
                'ansible_ssh_private_key_file': '~/.ssh/dnsscience-prod.pem',
                'ansible_ssh_common_args': '-o StrictHostKeyChecking=no'
            }
        }
    }

    # Add EC2 instances to app_servers
    if 'ec2_instance_ids' in tf_outputs:
        instances = tf_outputs['ec2_instance_ids'].get('value', [])
        for idx, instance_id in enumerate(instances):
            host_name = f"app-{idx + 1}"
            # Note: In real deployment, you'd get the actual IP from AWS API
            inventory['all']['children']['app_servers']['hosts'][host_name] = {
                'instance_id': instance_id,
                'ansible_host': f"<EC2_IP_{idx + 1}>",  # Placeholder
            }

    # Add RDS endpoint (managed service, no direct Ansible access)
    if 'rds_endpoint' in tf_outputs:
        inventory['all']['children']['db_servers']['vars']['rds_endpoint'] = \
            tf_outputs['rds_endpoint'].get('value', '')

    # Add Redis endpoint (managed service, no direct Ansible access)
    if 'redis_endpoint' in tf_outputs:
        inventory['all']['children']['cache_servers']['vars']['redis_endpoint'] = \
            tf_outputs['redis_endpoint'].get('value', '')

    # Add ALB DNS
    if 'alb_dns_name' in tf_outputs:
        inventory['all']['vars']['alb_dns_name'] = \
            tf_outputs['alb_dns_name'].get('value', '')

    return inventory

def save_inventory(inventory, output_path):
    """Save inventory to YAML file"""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)
        print(f"✓ Inventory generated: {output_path}")
    except Exception as e:
        print(f"Error saving inventory: {e}")
        sys.exit(1)

def main():
    """Main function"""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Paths
    tf_outputs_file = project_root / 'terraform-outputs.json'
    inventory_file = project_root / 'ansible' / 'inventory' / 'hosts.yml'

    print("=" * 50)
    print("Generating Ansible Inventory from Terraform")
    print("=" * 50)
    print()

    # Load Terraform outputs
    print(f"Loading Terraform outputs from: {tf_outputs_file}")
    tf_outputs = load_terraform_outputs(tf_outputs_file)

    # Generate inventory
    print("Generating inventory structure...")
    inventory = generate_inventory(tf_outputs)

    # Save inventory
    print(f"Saving inventory to: {inventory_file}")
    save_inventory(inventory, inventory_file)

    print()
    print("=" * 50)
    print("✓ Inventory generation complete!")
    print("=" * 50)
    print()
    print("Note: Update <EC2_IP_X> placeholders with actual IPs from AWS console")
    print("      or use dynamic inventory script with AWS EC2 plugin")

if __name__ == '__main__':
    main()
