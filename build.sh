#!/bin/bash

# Install only the basic dependencies needed for the demo to run
pip install flask==2.2.3 werkzeug==2.2.3 numpy==1.23.5 pandas==1.5.3 Pillow==9.4.0 matplotlib==3.7.0

# Create necessary directories
mkdir -p src/yara_rules
mkdir -p temp_uploads

echo "Build completed successfully" 