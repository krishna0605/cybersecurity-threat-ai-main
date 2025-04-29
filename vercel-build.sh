#!/bin/bash

# Make sure we have the templates directory in the right place
echo "Setting up templates directory for Flask..."
mkdir -p .vercel/src/templates

# If templates directory exists in src
if [ -d "src/templates" ]; then
  echo "Copying templates from src/templates..."
  cp -r src/templates/* .vercel/src/templates/
fi

# If templates directory exists at project root
if [ -d "templates" ]; then
  echo "Copying templates from templates..."
  cp -r templates/* .vercel/src/templates/
fi

echo "Build completed" 