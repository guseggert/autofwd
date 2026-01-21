# VHS demo script for autofwd
# https://github.com/charmbracelet/vhs

# Output settings
Output docs/demo.gif
Set Width 100
Set Height 20
Set FontSize 14
Set Theme "Dracula"
Set Padding 10
Set TypingSpeed 50ms

# Start autofwd connecting to demo server
Type "autofwd testuser@localhost -p 2222"
Enter

# Wait for connection and port detection
Sleep 4s

# Navigate down to select PostgreSQL port (row 2)
Down
Sleep 400ms
Down
Sleep 600ms

# Toggle the port off with space
Type " "
Sleep 2s
