# VHS demo script for autofwd
# https://github.com/charmbracelet/vhs

# Output settings  
Output docs/demo.gif
Set Width 100
Set Height 30
Set FontSize 16
Set FontFamily "DejaVu Sans Mono"
Set Theme "Dracula"
Set Padding 10
Set TypingSpeed 50ms

# First, verify autofwd works by showing help
Type "autofwd --help"
Enter
Sleep 2s

# Then run it with the SSH connection
Type "autofwd testuser@localhost -- -p 2222 -i /tmp/demo_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
Enter

# Wait for connection and port detection
Sleep 6s

# Navigate down to select PostgreSQL port
Down
Sleep 400ms
Down
Sleep 600ms

# Toggle the port off with space
Type " "
Sleep 2s

# Quit
Type "q"
Sleep 500ms
Type "y"
Sleep 1s
