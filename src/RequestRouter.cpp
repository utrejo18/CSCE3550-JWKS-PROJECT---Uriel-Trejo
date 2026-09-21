#include "RequestRouter.h"
using namespace std;

RequestRouter::RequestRouter(const KeyManager& manager,
                             const JwtService& service)
    : keyManager(manager), jwtService(service) {
}

HttpResponse RequestRouter::handleRequest(const HttpRequest& request) const {
    //This removes the query string so that only the endpoint path remains
    string path = request.target;
    size_t questionMark = path.find('?');

    if (questionMark != string::npos) {
        path = path.substr(0, questionMark);
    }

    //This handles the standard JWKS endpoint
    if (path == "/.well-known/jwks.json") {
        if (request.method != "GET") {
            return {405, "application/json",
                    "{\"error\":\"method_not_allowed\"}"};
        }

        //Kid filter is optional, empty means return all valid keys
        string wantedKid = getQueryValue(request.target, "kid");
        return {200, "application/json", keyManager.getJWKS(wantedKid)};
    }

    //This handles the fake authentication endpoint
    if (path == "/auth") {
        if (request.method != "POST") {
            return {405, "application/json",
                    "{\"error\":\"method_not_allowed\"}"};
        }

        //Check if client requested an expired token
        bool wantsExpiredToken =
            hasQueryParameter(request.target, "expired");

        return {200, "text/plain",
                jwtService.createToken(wantsExpiredToken)};
    }

    //Any path not listed above does not exist
    return {404, "application/json", "{\"error\":\"not_found\"}"};
}

bool RequestRouter::hasQueryParameter(const string& target,
                                      const string& name) {
    size_t questionMark = target.find('?');

    if (questionMark == string::npos) {
        return false;
    }

    //Start parsing the query string after the question mark
    size_t start = questionMark + 1;

    while (start <= target.length()) {
        size_t end = target.find('&', start);
        string item = target.substr(start, end - start);
        size_t equals = item.find('=');
        string itemName = item.substr(0, equals);

        if (itemName == name) {
            return true;
        }

        if (end == string::npos) {
            break;
        }

        start = end + 1;
    }

    return false;
}

//This retrieves the value of a query parameter by name
string RequestRouter::getQueryValue(const string& target,
                                    const string& name) {
    size_t questionMark = target.find('?');

    if (questionMark == string::npos) {
        return "";
    }

    size_t start = questionMark + 1;

    while (start <= target.length()) {
        size_t end = target.find('&', start);
        string item = target.substr(start, end - start);
        size_t equals = item.find('=');
        string itemName = item.substr(0, equals);

        if (itemName == name && equals != string::npos) {
            return item.substr(equals + 1);
        }

        if (end == string::npos) {
            break;
        }

        start = end + 1;
    }

    return "";
}
