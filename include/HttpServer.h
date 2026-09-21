#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "RequestRouter.h"

//Class called HttpServer that listens for HTTP requests and then sends response
class HttpServer {
public:
    HttpServer(const RequestRouter& router); 
    void listen(unsigned short port) const;

private:
    const RequestRouter& router_;
};

#endif
