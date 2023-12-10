#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <functional>

class SSLServer {
public:
    using ConnectionCallback = std::function<void(SSL*, int)>;

    SSLServer();
    ~SSLServer();

    void setConnectionCallback(ConnectionCallback callback);
    void startServer(int port);

private:
    void initOpenSSL();
    SSL_CTX* createContext();
    void handleConnection(SSL* ssl, int client_fd);
    void readFromClient(SSL* ssl, int client_fd);
    void writeToClient(SSL* ssl, const char* data);
    static void threadEntry(SSLServer* server, int client_fd);
    static int verifyClientCertificate(int preverify, X509_STORE_CTX* ctx);

    SSL_CTX* ctx;
    int server_fd;
    ConnectionCallback connectionCallback;
    std::mutex sslMutex; // Mutex to protect SSL operations
};

#endif // SSL_SERVER_H
