#!/bin/bash

# Check if node_modules exists
if [ -d "node_modules" ]; then
    echo "The node_modules directory exists. Running puppeteer_revolt.js..."
    node puppeteer_revolt.js
else
    echo "The node_modules directory does not exist. Running npm install..."
    npm install
    node puppeteer_revolt.js
fi

# Optional: pause-like behavior
read -p "Press ENTER to continue..."
