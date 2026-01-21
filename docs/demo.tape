# VHS demo script for autofwd
# https://github.com/charmbracelet/vhs

# Output settings
Output docs/demo.gif
Set Width 120
Set Height 25
Set FontSize 18
Set FontFamily "DejaVu Sans Mono"
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 50ms
Set Framerate 24

# Set shell to bash with proper environment
Set Shell "bash"

# Start autofwd connecting to demo server with explicit SSH options
Type "autofwd testuser@localhost -- -p 2222 -i /tmp/demo_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
Enter

# Wait for connection and port detection
Sleep 5s

# Navigate down to select PostgreSQL port (row 2)
Down
Sleep 400ms
Down
Sleep 600ms

# Toggle the port off with space
Type " "
Sleep 2s
