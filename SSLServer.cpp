#include "SSLServer.h"
#include <iostream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <vector>
#include <mutex>

#define BUFFER_SIZE 1024
#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"
#define CA_CERT "ca.crt"

SSLServer::SSLServer() {
    initOpenSSL();
    ctx = createContext();
}

SSLServer::~SSLServer() {
    close(server_fd);
    SSL_CTX_free(ctx);
}

void SSLServer::initOpenSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* SSLServer::createContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* context = SSL_CTX_new(method);

    if (!context) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error creating SSL context");
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(context, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading server certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(context, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading server private key");
    }

    // Load CA certificates for client verification
    if (SSL_CTX_load_verify_locations(context, CA_CERT, nullptr) == 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading CA certificates");
    }

    // Set up client verification
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verifyClientCertificate);
    SSL_CTX_set_verify_depth(context, 1);

    return context;
}

void SSLServer::handleConnection(SSL* ssl, int client_fd) {
    try {
        char buffer[BUFFER_SIZE];

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            std::cerr << "Error performing SSL handshake" << std::endl;
            close(client_fd);
            return;
        }

        // Read data from the client
        readFromClient(ssl, client_fd);

        // Respond to the client
        const char* response = "Hello from server!";
        writeToClient(ssl, response);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        std::cout << "Connection closed." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception in handleConnection: " << e.what() << std::endl;
    }
}

void SSLServer::readFromClient(SSL* ssl, int client_fd) {
    char buffer[BUFFER_SIZE];

    std::lock_guard<std::mutex> lock(sslMutex);
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        int sslError = SSL_get_error(ssl, bytes);
        if (sslError == SSL_ERROR_ZERO_RETURN || sslError == SSL_ERROR_SYSCALL) {
            // Connection closed by client
            std::cout << "Client disconnected." << std::endl;
        } else {
            // Other SSL/TLS error
            ERR_print_errors_fp(stderr);
        }
        return;
    }

    buffer[bytes] = '\0';
    std::cout << "Received: " << buffer << std::endl;
}

void SSLServer::writeToClient(SSL* ssl, const char* data) {
    std::lock_guard<std::mutex> lock(sslMutex);
    SSL_write(ssl, data, strlen(data));
}

void SSLServer::threadEntry(SSLServer* server, int client_fd) {
    SSL* ssl = SSL_new(server->ctx);
    SSL_set_fd(ssl, client_fd);

    if (server->connectionCallback) {
        // If a callback is set, call it with SSL and client_fd
        server->connectionCallback(ssl, client_fd);
    } else {
        // Otherwise, use the default handleConnection function
        server->handleConnection(ssl, client_fd);
    }
}

void SSLServer::setConnectionCallback(ConnectionCallback callback) {
    connectionCallback = std::move(callback);
}

int SSLServer::verifyClientCertificate(int preverify, X509_STORE_CTX* ctx) {
    if (preverify == 0) {
        // Pre-verification failed, do not accept the certificate
        return 0;
    }

    // Retrieve the client certificate
    X509* clientCert = X509_STORE_CTX_get_current_cert(ctx);

    // Perform additional verification if needed

    // Example: Verify that the client certificate has a common name (CN) field
    if (X509_NAME* subjectName = X509_get_subject_name(clientCert)) {
        char commonName[256];
        if (X509_NAME_get_text_by_NID(subjectName, NID_commonName, commonName, sizeof(commonName)) > 0) {
            // Check commonName as needed
        } else {
            // Common name not found, reject the certificate
            return 0;
        }
    } else {
        // Unable to get subject name, reject the certificate
        return 0;
    }

    // Example: Check additional conditions if needed

    return 1;  // Accept the client certificate
}
