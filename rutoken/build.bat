call nw-gyp configure --target=0.12.3 --arch=ia32
call nw-gyp build
copy C:\GitHub\RutokenJS\app\rutoken\build\Release\rutoken.node C:\GitHub\RutokenJS\app\rutoken\rutoken.node
call C:\GitHub\RutokenJS\nw C:\GitHub\RutokenJS\app