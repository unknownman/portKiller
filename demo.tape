Output assets/demo.gif
Require pk
Require python3

Set FontSize 16
Set Width 1100
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful

Hide
# Start dummy servers in the background to occupy ports
Type "python3 -m http.server 3000 > /dev/null 2>&1 &"
Enter
Type "python3 -m http.server 8080 > /dev/null 2>&1 &"
Enter
Type "clear"
Enter
Show

Sleep 1s
Type "pk 3000"
Sleep 500ms
Enter
Sleep 4s

Type "pk 3000 8080"
Sleep 500ms
Enter
Sleep 4s

Type "pk --json 3000"
Sleep 500ms
Enter
Sleep 4s

Type "pk --kill 3000"
Sleep 500ms
Enter
Sleep 2s
Type "N"
Enter
Sleep 2s

Type "pk --force 8080"
Sleep 500ms
Enter
Sleep 4s

Type "pk 8080"
Sleep 500ms
Enter
Sleep 3s

Hide
# Cleanup background processes
Type "kill -9 $(jobs -p)"
Enter
