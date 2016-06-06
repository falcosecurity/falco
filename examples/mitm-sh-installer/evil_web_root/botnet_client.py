import socket;
import signal;
import os;

os.close(0);
os.close(1);
os.close(2);

signal.signal(signal.SIGINT,signal.SIG_IGN);
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('0.0.0.0', 1234))
serversocket.listen(5);
while 1:
    (clientsocket, address) = serversocket.accept();
    clientsocket.send('Waiting for botnet command and control commands...\n');
    command = clientsocket.recv(1024)
    clientsocket.send('Ok, will execute "{}"\n'.format(command.strip()))
    clientsocket.close()
