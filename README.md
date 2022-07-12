# http-client

This libary provides a "Golang Functional Options Pattern" implementation for the "net/http" client.

Supported options are:
| Option                      | Function                                                                                                                                                                  |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Debug                       | Print debugging info to provided logger.                                                                                                                                  |
| UserAgent                   | Change the UserAgent header, if not set.                                                                                                                                  |
| Timeout                     | Set the client request timeout.                                                                                                                                           |
| DisableHttp2                | Disable HTTP2 connections.                                                                                                                                                |
| Http2Transport              | Configure HTTP2 transport.                                                                                                                                                |
| AutoDeflate                 | Disable automatic deflation of gzip responses.                                                                                                                            |
| DisableCompression          | Remove Accept-Encoding: gzip header; and don't deflate responses.                                                                                                         |
| AuthProxy                   | Add auth proxy headers to requests.                                                                                                                                       |
| BasicAuth                   | Set basic auth header.                                                                                                                                                    |
| BearerAuth                  | Set bearer auth header.                                                                                                                                                   |
| BearerAuthWithRefresh       | Set bearer auth header, with refresh from file.                                                                                                                           |
| DialContext                 | Configure alternative DialContext function.                                                                                                                               |
| MaxIdleConnsPerHost         | Configure MaxIdleConnsPerHost.                                                                                                                                            |
| Proxy                       | Configure Proxy.                                                                                                                                                          |
| TLSClientCertificate        | Use provided ClientCertificate function to determine what tls certificate to use for client authentication.                                                               |
| TLSDynamicClientCertificate | Use provided DynamicClientCertificateSource to dynamically determine what tls certificate to use for client authentication, also closes existing connections when needed. |
| TLSRootCAs                  | Use provided CertPool to verify the server certificate.                                                                                                                   |
| TLSDynamicRootCAs           | Use provided DynamicRootCAsSource to dynamically verify the server certificate.                                                                                           |
| TLSEnableSni                | Set SNI ServerName based on the request Host field.                                                                                                                       |
| TLSInsecureSkipVerify       | Insecure TLS skip verify                                                                                                                                                  |
| TLSTime                     | Set Time function to use for TLS, usefull for testing.                                                                                                                    |
|---|---|
| StartDynamicFileClientCertificateSource | Start a dynamic file-backed Client Certificate source that can be provided to TLSDynamicClientCertificate |
| StartDynamicFileRootCAsSource | Start a dynamic file-backed Client RootCA source that can be provided to TLSDynamicRootCAs |
