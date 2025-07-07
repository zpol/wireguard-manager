#!/bin/sh
set -e

# Asegura que el directorio existe
mkdir -p /root/.ssh

# Añade las huellas de los nodos si la variable está definida
if [ -n "$SSH_NODES" ]; then
  ssh-keyscan $SSH_NODES >> /root/.ssh/known_hosts || true
fi

# Arranca el backend
exec ./main 