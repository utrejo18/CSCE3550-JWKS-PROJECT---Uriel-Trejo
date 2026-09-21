#include <csignal>
#include <iostream>
#include "HttpServer.h"
#include "JwtService.h"
#include "KeyManager.h"
#include "RequestRouter.h"

int main() {
    using namespace std;

    //This prevents the program from ending if a client disconnects while the data is being sent
    signal(SIGPIPE, SIG_IGN);

    //This makes the objects used by the program 
    KeyManager keyManager;
    JwtService jwtService(keyManager);
    RequestRouter router(keyManager, jwtService);
    HttpServer server(router);

    //Since port 8080 is needed
    server.listen(8080);

    return 0;
}
