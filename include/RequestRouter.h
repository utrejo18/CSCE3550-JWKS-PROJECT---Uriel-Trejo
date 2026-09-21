#ifndef REQUEST_ROUTER_H
#define REQUEST_ROUTER_H

#include <string>
#include "JwtService.h"
#include "KeyManager.h"

//This struct for HTTP requests uses method, target, and body to represent a request
struct HttpRequest {
    std::string method;
    std::string target;
    std::string body;
};

//What this struct does is that it uses status, contentType, and body to represent a response
struct HttpResponse {
    int status;
    std::string contentType;
    std::string body;
};

//What this class does is that it routes HTTP requests to the correct endpoint and then it returns the correct response
//Uses KeyManager to get the keys and then JWTService to create the JWT token
class RequestRouter {
public:
    RequestRouter(const KeyManager& manager, const JwtService& service);

    //Decide which endpoint was requested and then build its response
    HttpResponse handleRequest(const HttpRequest& request) const;

    //These are public so that they can also be tested directly
    static bool hasQueryParameter(const std::string& target,
                                  const std::string& name);
    static std::string getQueryValue(const std::string& target,
                                     const std::string& name);

private:
    const KeyManager& keyManager;
    const JwtService& jwtService;
};

#endif
