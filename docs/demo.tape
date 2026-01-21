# VHS demo script for autofwd
Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 120
Set Height 120
Set Theme "Dracula"

Type "autofwd testuser@localhost -- -p 2222 -i /tmp/demo_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
Enter
Sleep 5s

# Navigate down and toggle a port
Down
Sleep 300ms
Down
Sleep 300ms
Space
Sleep 2s
