# VHS demo script for autofwd
Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 500
Set Theme "Dracula"
Set TypingSpeed 100ms

Type "autofwd demo --allow 3000,5432,6379"
Enter
Sleep 1s

# Wait for connection and all ports to appear
Sleep 6s

# Navigate down and toggle a port
Down
Sleep 400ms
Down
Sleep 400ms
Space
Sleep 2s
