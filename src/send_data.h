#pragma once

void create_connection(char *address, char *port);
void close_connection();
int send_data(struct flow flow);