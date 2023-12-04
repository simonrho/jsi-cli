#!/bin/sh

# ANSI escape code for bold and blue text
BLUE_BOLD="\033[1;34m"
# ANSI escape code to reset text style
RESET="\033[0m"

echo ""
echo -e "Starting the installation of the Juniper ${BLUE_BOLD}JSI CLI${RESET} script...\n"

# Step 1: Download the jsi-cli script
curl -k -s https://raw.githubusercontent.com/simonrho/jsi-cli/main/jsi.py -o /var/db/scripts/op/jsi 
CURL_EXIT_CODE=$?

# Check for specific curl error codes
if [ $CURL_EXIT_CODE -eq 6 ]; then
    echo "Error: The host could not be resolved."
    exit 6
elif [ $CURL_EXIT_CODE -eq 28 ]; then
    echo "Error: Timeout was reached."
    exit 28
elif [ $CURL_EXIT_CODE -ne 0 ]; then
    echo "Error: An error occurred with curl. Exit code: $CURL_EXIT_CODE"
    exit $CURL_EXIT_CODE
else
    echo -e "1. The ${BLUE_BOLD}jsi-cli${RESET} script has been successfully downloaded."
fi

# Step 2: Register the jsi-cli script in the system
COMMANDS=$(cat <<'EOF'
edit
set system scripts language python3
set system scripts op file jsi
commit and-quit
EOF
)

# Convert the multi-line string into a single line string
COMMANDS_ONE_LINE=$(echo "$COMMANDS" | tr '\n' ';')

# Ensure the last command doesn't end with an unnecessary semicolon
COMMANDS_ONE_LINE=${COMMANDS_ONE_LINE%;}

# Use the concatenated command string
/usr/sbin/cli -c "$COMMANDS_ONE_LINE" > /dev/null
CLI_EXIT_CODE=$?

if [ $CLI_EXIT_CODE -ne 0 ]; then
    echo "Error: An error occurred while registering the jsi-cli script. Exit code: $CLI_EXIT_CODE"
    exit $CLI_EXIT_CODE
else
    echo -e "2. The ${BLUE_BOLD}jsi-cli${RESET} script has been successfully registered in the system.\n"
fi

# Final message
echo -e "Installation complete!"
echo -e "Please run the '${BLUE_BOLD}op jsi${RESET}' command to execute the script.\n"
