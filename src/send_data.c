/*

 Simple echo connected UDP client with two parameters and the connect() function

 Usage: echo-udp-client2 <server IP address/domain name> <port number>

 (c) Petr Matousek, 2016

 Last update: Sept 2019

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include "send_data.h"

#define BUFFER 1024 // buffer length

int sock; // socket descriptor
int msg_size, i;
struct sockaddr_in server, from; // address structures of the server and the client
struct hostent *servent;         // network host entry required by gethostbyname()
socklen_t len, fromlen;
char buffer[BUFFER];

void create_connection(char *address, char *port)
{
  memset(&server, 0, sizeof(server)); // erase the server structure
  server.sin_family = AF_INET;

  // make DNS resolution of the first parameter using gethostbyname()
  if ((servent = gethostbyname(address)) == NULL) // check the first parameter
    errx(1, "gethostbyname() failed\n");

  // copy the first parameter to the server.sin_addr structure
  memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

  server.sin_port = htons(atoi(port)); // server port (network byte order)

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create a client socket
    err(1, "socket() failed\n");

  printf("* Server socket created\n");

  len = sizeof(server);
  fromlen = sizeof(from);

  printf("* Creating a connected UDP socket using connect()\n");
  // create a connected UDP socket
  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1)
    err(1, "connect() failed");
}

void close_connection()
{
  close(sock);
  printf("* Closing the client socket ...\n");
}

int send_data()
{
  // send data to the server
  while ((msg_size = read(STDIN_FILENO, buffer, BUFFER)) > 0)
  // read input data from STDIN (console) until end-of-line (Enter) is pressed
  // when end-of-file (CTRL-D) is received, n == 0
  {
    i = send(sock, buffer, msg_size, 0); // send data to the server
    if (i == -1)                         // check if data was sent correctly
      err(1, "send() failed");
    else if (i != msg_size)
      err(1, "send(): buffer written partially");

    // obtain the local IP address and port using getsockname()
    if (getsockname(sock, (struct sockaddr *)&from, &len) == -1)
      err(1, "getsockname() failed");

    printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr), ntohs(server.sin_port), server.sin_port);

    // read the answer from the server
    if ((i = recv(sock, buffer, BUFFER, 0)) == -1)
      err(1, "recv() failed");
    else if (i > 0)
    {
      // obtain the remote IP adddress and port from the server (cf. recfrom())
      if (getpeername(sock, (struct sockaddr *)&from, &fromlen) != 0)
        err(1, "getpeername() failed\n");

      printf("* UDP packet received from %s, port %d\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
      printf("%.*s", i, buffer); // print the answer
    }
  }
  // reading data until end-of-file (CTRL-D)

  if (msg_size == -1)
    err(1, "reading failed");

  return 0;
}
