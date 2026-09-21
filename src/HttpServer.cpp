#include "HttpServer.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

//This function returns a reason for the HTTP status code, which is then used in the HTTP response
string reasonPhrase(int status) {
    // The text shown after an HTTP status code.
    if (status == 200) return "OK";
    if (status == 404) return "Not Found";
    if (status == 405) return "Method Not Allowed";
    return "Internal Server Error";
}
//This sends all the data in the string to the socket, which is then used to send the HTTP response
void sendAll(int socketNumber, const string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t amount = send(socketNumber, data.data() + sent,
                              data.size() - sent, 0);
        if (amount <= 0) return;
        sent += static_cast<size_t>(amount);
    }
}
//This reads the HTTP request from the socket and then returns it as an HTTP request struct
//After that, the HTTP request is then used to figure out what the HTTP response should be
HttpRequest readRequest(int client) {
    string raw;
    char buffer[4096];
    //Reads request until the end of the headers is reached or until 64 KB of data is read
    while (raw.find("\r\n\r\n") == string::npos && raw.size() < 65536) {
        ssize_t received = recv(client, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        raw.append(buffer, static_cast<size_t>(received));
    }
    istringstream stream(raw); //Reads first line of HTTP request
    HttpRequest request; //Fills in HTTP request struct with method, target, and body from HTTP request

    //The first line of the HTTP request contains target and method, which are then used to figure out what the HTTP response should be
    stream >> request.method >> request.target;
    size_t bodyStart = raw.find("\r\n\r\n");
    if (bodyStart != string::npos) request.body = raw.substr(bodyStart + 4);
    return request;
}

HttpServer::HttpServer(const RequestRouter& router) : router_(router) {}

//This function listens for HTTP requests and then sends the HTTP response back to the client
void HttpServer::listen(unsigned short port) const {
    //A socket lets the program to receive network connections
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        cerr << "Could not create the server socket " << endl;
        exit(1);
    }

    int reuse = 1;
    //This just makes it a bit easier to restart the program on the same port
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in address{};
    //Listen on all networks and port 8080
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    //If the port is already in use, then the program will exit with a message
    if (::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        ::listen(server, 16) < 0) {
        cerr << "Could not start the server. Port 8080 may already be in use."
             << endl;
        close(server);
        exit(1);
    }

    cout << "JWKS server listening on http://localhost:" << port << endl;
    while (true) {
        //Waits for a client to connect, then connection is accepted and the client socket is returned
        int client = accept(server, nullptr, nullptr);
        if (client < 0) continue;

        //Reads HTTP request from client, then uses HTTP request to figure what HTTP response should be
        //and then sends response back to client
        HttpRequest request = readRequest(client);
        HttpResponse response = router_.handleRequest(request);

        //Builda HTTP response
        string message = "HTTP/1.1 " + to_string(response.status) + " " +
            reasonPhrase(response.status) + "\r\n";
        message += "Content-Type: " + response.contentType + "\r\n";
        message += "Content-Length: " + to_string(response.body.size()) + "\r\n";
        message += "Connection: close\r\n\r\n";
        message += response.body;

        sendAll(client, message);
        close(client);
    }
}
