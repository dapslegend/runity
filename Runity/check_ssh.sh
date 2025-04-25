#!/bin/bash

# Load environment variables
source .env

# Parse SSH_HOSTS
IFS=',' read -ra HOSTS <<< "$SSH_HOSTS"

for HOST in "${HOSTS[@]}"; do
    IFS=':' read -r IP PASS <<< "$HOST"
    sshpass -p "$PASS" ssh -o ConnectTimeout=10 "$SSH_USER@$IP" "echo 'SSH connection successful'" || {
        echo "Failed to connect to $IP"
        exit 1
    }
done

echo "All SSH connections successful"
