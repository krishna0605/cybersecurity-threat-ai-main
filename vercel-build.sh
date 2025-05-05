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

# Create necessary directories for the application
echo "Creating necessary directories..."
mkdir -p .vercel/src/yara_rules
mkdir -p .vercel/temp_uploads

# Create static directory if it exists
if [ -d "src/static" ]; then
  echo "Copying static files..."
  mkdir -p .vercel/src/static
  cp -r src/static/* .vercel/src/static/
fi

echo "Build completed" 