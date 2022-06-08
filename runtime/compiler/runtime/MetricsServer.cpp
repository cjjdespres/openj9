/*******************************************************************************
 * Copyright (c) 2022, 2022 IBM Corp. and others
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] http://openjdk.java.net/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>	/* for TCP_NODELAY option */
#include <openssl/err.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // read, write

#include "control/CompilationRuntime.hpp"
#include "control/Options.hpp"
#include "env/TRMemory.hpp"
#include "env/PersistentInfo.hpp"
#include "env/VerboseLog.hpp"
#include "env/VMJ9.h"
#include "runtime/MetricsServer.hpp"

bool MetricsServer::useSSL(TR::CompilationInfo *compInfo)
   {
   return (compInfo->getJITServerMetricsSslKeys().size() || compInfo->getJITServerMetricsSslCerts().size());
   }

static SSL_CTX *
createSSLContext(TR::CompilationInfo *compInfo)
   {
   SSL_CTX *ctx = (*OSSL_CTX_new)((*OSSLv23_server_method)());

   if (!ctx)
      {
      perror("can't create SSL context");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }

   const char *sessionIDContext = "MetricsServer";
   (*OSSL_CTX_set_session_id_context)(ctx, (const unsigned char*)sessionIDContext, strlen(sessionIDContext));

   if ((*OSSL_CTX_set_ecdh_auto)(ctx, 1) != 1)
      {
      perror("failed to configure SSL ecdh");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }

   auto &sslKeys = compInfo->getJITServerMetricsSslKeys();
   auto &sslCerts = compInfo->getJITServerMetricsSslCerts();

   TR_ASSERT_FATAL(sslKeys.size() == 1 && sslCerts.size() == 1, "only one key and cert is supported for now");

   // Parse and set private key
   BIO *keyMem = (*OBIO_new_mem_buf)(&sslKeys[0][0], sslKeys[0].size());
   if (!keyMem)
      {
      perror("cannot create memory buffer for private key (OOM?)");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }
   EVP_PKEY *privKey = (*OPEM_read_bio_PrivateKey)(keyMem, NULL, NULL, NULL);
   if (!privKey)
      {
      perror("cannot parse private key");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }
   if ((*OSSL_CTX_use_PrivateKey)(ctx, privKey) != 1)
      {
      perror("cannot use private key");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }

   // Parse and set certificate
   BIO *certMem = (*OBIO_new_mem_buf)(&sslCerts[0][0], sslCerts[0].size());
   if (!certMem)
      {
      perror("cannot create memory buffer for cert (OOM?)");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }
   X509 *certificate = (*OPEM_read_bio_X509)(certMem, NULL, NULL, NULL);
   if (!certificate)
      {
      perror("cannot parse cert");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }
   if ((*OSSL_CTX_use_certificate)(ctx, certificate) != 1)
      {
      perror("cannot use cert");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }

   // Verify key and cert are valid
   if ((*OSSL_CTX_check_private_key)(ctx) != 1)
      {
      perror("private key check failed");
      (*OERR_print_errors_fp)(stderr);
      exit(1);
      }

   // verify server identity using standard method
   (*OSSL_CTX_set_verify)(ctx, SSL_VERIFY_PEER, NULL);

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer: Successfully initialized SSL context (%s)\n", (*OOpenSSL_version)(0));

   return ctx;
   }

static bool
handleOpenSSLConnectionError(int connfd, SSL *&ssl, BIO *&bio, const char *errMsg)
   {
   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
       TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "%s: errno=%d", errMsg, errno);
   (*OERR_print_errors_fp)(stderr);

   close(connfd);
   if (bio)
      {
      (*OBIO_free_all)(bio);
      bio = NULL;
      }
   return false;
   }

static bool acceptOpenSSLConnection(SSL_CTX *sslCtx, int connfd, BIO *bio)
   {
   SSL *ssl = NULL;
   bio = (*OBIO_new_ssl)(sslCtx, false);
   if (!bio)
      return handleOpenSSLConnectionError(connfd, ssl, bio, "Error creating new BIO");

   if ((*OBIO_ctrl)(bio, BIO_C_GET_SSL, false, (char *) &ssl) != 1) // BIO_get_ssl(bio, &ssl)
      return handleOpenSSLConnectionError(connfd, ssl, bio, "Failed to get BIO SSL");

   if ((*OSSL_set_fd)(ssl, connfd) != 1)
      return handleOpenSSLConnectionError(connfd, ssl, bio, "Error setting SSL file descriptor");

   if ((*OSSL_accept)(ssl) <= 0)
      return handleOpenSSLConnectionError(connfd, ssl, bio, "Error accepting SSL connection");

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "SSL connection on socket 0x%x, Version: %s, Cipher: %s\n",
                                                     connfd, (*OSSL_get_version)(ssl), (*OSSL_get_cipher)(ssl));
   return true;
   }

double CPUUtilMetric::computeValue(TR::CompilationInfo *compInfo)
   {
   CpuUtilization *cpuUtil = compInfo->getCpuUtil();
   if (cpuUtil->isFunctional())
      {
      setValue(cpuUtil->getVmCpuUsage());
      }
   return getValue();
   }

double AvailableMemoryMetric::computeValue(TR::CompilationInfo *compInfo)
   {
   setValue(compInfo->getCachedFreePhysicalMemoryB());
   return getValue();
   }

double ConnectedClientsMetric::computeValue(TR::CompilationInfo *compInfo)
   {
   // Accessing clientSessionHT without a lock. This is just
   // for information purposes and getting the slightly wrong
   // value (rarely) may not matter
   setValue(compInfo->getClientSessionHT()->size());
   return getValue();
   }

double ActiveThreadsMetric::computeValue(TR::CompilationInfo *compInfo)
   {
   setValue(compInfo->getNumCompThreadsActive());
   return getValue();
   }

MetricsDatabase::MetricsDatabase(TR::CompilationInfo *compInfo) : _compInfo(compInfo)
   {
   _metrics[0] = new (PERSISTENT_NEW) CPUUtilMetric();
   _metrics[1] = new (PERSISTENT_NEW) AvailableMemoryMetric();
   _metrics[2] = new (PERSISTENT_NEW) ConnectedClientsMetric();
   _metrics[3] = new (PERSISTENT_NEW) ActiveThreadsMetric();
   static_assert(3 == MAX_METRICS - 1);
   }

MetricsDatabase::~MetricsDatabase()
   {
   for (int i =0; i < MAX_METRICS; i++)
      {
      _metrics[i]->~PrometheusMetric();
      TR_Memory::jitPersistentFree(_metrics[i]);
      }
   }

std::string
MetricsDatabase::serializeMetrics()
   {
   std::string output;
   for (int i =0; i < MAX_METRICS; i++)
      {
      _metrics[i]->computeValue(_compInfo);
      output.append(_metrics[i]->serialize());
      }
   return output;
   }

HttpGetRequest::ReturnCodes
HttpGetRequest::readHttpGetRequest()
   {
   size_t capacityLeft = BUF_SZ - 1 - _msgLength; // subtract 1 for NULL terminator
   int bytesRead = 0;
   if (_ssl)
      {
      bytesRead = (*OBIO_read)(_ssl, _buf + _msgLength, capacityLeft);
      // Even though we waited with poll(), there may still not be enough data available in the SSL case
      if ((bytesRead <= 0) && (*OBIO_should_retry)(_ssl))
         {
         return INCOMPLETE_REQUEST;
         }
      }
   else
      {
      // Unlike the SSL case, there is guaranteed to be some data to read here because of poll()
      bytesRead = read(_sockfd, _buf + _msgLength, capacityLeft);
      }

   if (bytesRead <= 0)
      {
      fprintf(stderr, "Error reading from socket %d ", _sockfd);
      perror("");
      return READ_ERROR;
      }
   // Must have at least GET, one space, one path, one space, http protocol and CR LF
   if (_msgLength == 0)
      {
      // This is the first read on this socket. Make sure it starts with GET
      if (bytesRead < 4)
         {
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer: Too few bytes received when reading from socket  %d\n", socket);
         return READ_ERROR;
         }
      if (strncmp(_buf, "GET ", 4) != 0)
         return NO_GET_REQUEST; // We only accept GET requests
      }
   _msgLength += bytesRead;
   _buf[_msgLength] = 0; // NULL string terminator

   // Check that we got the entire message. The GET request should end with a double CR LF sequence.
   char *endOfRequestPtr = strstr(_buf, "\r\n\r\n");
   if (!endOfRequestPtr)
      {
      // Incomplete message
      if (_msgLength >= BUF_SZ-1) // No more space to read
         return REQUEST_TOO_LARGE;
      return INCOMPLETE_REQUEST; // Will have to read more data
      }
   return FULL_REQUEST_RECEIVED;
   }

HttpGetRequest::ReturnCodes
HttpGetRequest::parseHttpGetRequest()
   {
   // Parse my message. Expect something like:
   // GET /metrics HTTP/1.1
   // Host: 127.0.0.1:9403
   // User-Agent: Prometheus/2.31.1
   // Accept: application/openmetrics-text; version=0.0.1,text/plain;version=0.0.4;q=0.5,*/*;q=0.1
   // Accept-Encoding: gzip
   // X-Prometheus-Scrape-Timeout-Seconds: 3
   static const char *MetricsPath = "/metrics";
   static const size_t MetricsPathLength = strlen(MetricsPath);
   static const char *tokenSeparators = " \r\n";
   static const char *endLineSequence = "\r\n";

   _buf[BUF_SZ-1] = 0; // make sure our string routines will find an end of string
   // We already checked that the message starts with "GET "
   size_t pos = 4;

   // Jump over spaces
   while (pos < _msgLength && _buf[pos] == ' ')
      pos++;
   if (pos >= _msgLength)
      return MALFORMED_REQUEST;

   // Get the path
   size_t pathLength = strcspn(_buf + pos, tokenSeparators);
   if (pathLength > HttpGetRequest::MAX_PATH_LENGTH - 1)
      return REQUEST_URI_TOO_LONG;
   // TODO: process absolute paths like http://server:port/metrics. Absolute paths always have ":" in them
   // Here we want to check the received path against well known strings like "/metrics", "/liveness", "/readiness"
   if (pathLength == MetricsPathLength && strncmp(_buf+pos, MetricsPath, pathLength) == 0)
      _path = Path::Metrics;
   else
      return INVALID_PATH;

   // Jump over path
   pos += pathLength;

   // Must have at least one space
   if (_buf[pos++] != ' ')
      return MALFORMED_REQUEST;
   // Jump over spaces
   while (pos < _msgLength && _buf[pos] == ' ')
      pos++;
   if (pos >= _msgLength)
      return MALFORMED_REQUEST;

   // Get the Http protocol; expect something like HTTP/1.1 or HTTP/1
   static const size_t MAX_HTTP_VERSION_STRING_SIZE = 8; // e.g HTTP/1.1 (major.minor)
   static const size_t MIN_HTTP_VERSION_STRING_SIZE = 6; // e.g HTTP/2
   size_t protocolLength = strcspn(_buf + pos, tokenSeparators);
   if (protocolLength < MIN_HTTP_VERSION_STRING_SIZE || protocolLength > MAX_HTTP_VERSION_STRING_SIZE)
      return INVALID_HTTP_PROTOCOL;
   static const char *HTTP_VERSION_HEADER_STRING = "HTTP/";
   static const size_t HTTP_VERSION_HEADER_STRING_SIZE = strlen(HTTP_VERSION_HEADER_STRING);
   if (strncmp(_buf+pos, HTTP_VERSION_HEADER_STRING, HTTP_VERSION_HEADER_STRING_SIZE))
      return INVALID_HTTP_PROTOCOL;
   memcpy(_httpVersion, _buf+pos+HTTP_VERSION_HEADER_STRING_SIZE, protocolLength-HTTP_VERSION_HEADER_STRING_SIZE);
   _httpVersion[protocolLength-HTTP_VERSION_HEADER_STRING_SIZE] = 0; // null terminator

   pos += protocolLength;
   // Find the "\r\n" sequence which ends the Request Line
   char *endOfRequestPtr = strstr(_buf+pos, endLineSequence);
   if (!endOfRequestPtr)
      return MALFORMED_REQUEST;

   // Now read the headers
   endOfRequestPtr += 2; // jump over "/r/n"
   // We know that we must have at least one other pair of "\r\n" at the very least
   char *endOfHeaderLine = strstr(endOfRequestPtr, endLineSequence);

   return HTTP_OK;
   }

HttpGetRequest::ReturnCodes
HttpGetRequest::sendHttpResponse()
   {
   int bytesWritten = 0;
   int remainingBytes = _response.length() - _responseBytesSent + 1; // add one for NULL terminator
   if (_ssl)
      {
      bytesWritten = (*OBIO_write)(_ssl, _response.c_str() + _responseBytesSent, remainingBytes);
      // Even though we waited with poll(), we may still not be able to send any data in the SSL case
      if ((bytesWritten <= 0) && (*OBIO_should_retry)(_ssl))
         {
         return INCOMPLETE_RESPONSE;
         }
      }
   else
      {
      // Unlike the SSL case, there will always be capacity to write data because we waited with poll()
      bytesWritten = write(_sockfd, _response.c_str() + _responseBytesSent, remainingBytes);
      }

   if (remainingBytes == bytesWritten)
      {
      return FULL_RESPONSE_SENT;
      }
   else if (bytesWritten > 0)
      {
      _responseBytesSent += bytesWritten;
      return INCOMPLETE_RESPONSE;
      }
   else
      {
      fprintf(stderr, "Error writing to socket %d ", _sockfd);
      perror("");
      return WRITE_ERROR;
      }
   }

MetricsServer::MetricsServer()
   : _metricsThread(NULL), _metricsMonitor(NULL), _metricsOSThread(NULL),
   _metricsThreadAttachAttempted(false), _metricsThreadExitFlag(false), _jitConfig(NULL), _sslCtx(NULL)
   {
   for (int i = 0; i < 1 + MAX_CONCURRENT_REQUESTS; i++)
      _pfd[i].fd = -1; // invalid
   }

MetricsServer * MetricsServer::allocate()
   {
   MetricsServer * metricsServer = new (PERSISTENT_NEW) MetricsServer();
   return metricsServer;
   }

static int32_t J9THREAD_PROC metricsThreadProc(void * entryarg)
   {
   J9JITConfig * jitConfig = (J9JITConfig *) entryarg;
   J9JavaVM * vm = jitConfig->javaVM;
   MetricsServer *metricsServer = ((TR_JitPrivateConfig*)(jitConfig->privateConfig))->metricsServer;
   metricsServer->setJITConfig(jitConfig);
   J9VMThread *metricsThread = NULL;
   PORT_ACCESS_FROM_JITCONFIG(jitConfig);

   int rc = vm->internalVMFunctions->internalAttachCurrentThread(vm, &metricsThread, NULL,
                                  J9_PRIVATE_FLAGS_DAEMON_THREAD | J9_PRIVATE_FLAGS_NO_OBJECT |
                                  J9_PRIVATE_FLAGS_SYSTEM_THREAD | J9_PRIVATE_FLAGS_ATTACHED_THREAD,
                                  metricsServer->getMetricsOSThread());

   metricsServer->getMetricsMonitor()->enter();
   metricsServer->setAttachAttempted(true);
   if (rc == JNI_OK)
      metricsServer->setMetricsThread(metricsThread);
   metricsServer->getMetricsMonitor()->notifyAll();
   metricsServer->getMetricsMonitor()->exit();
   if (rc != JNI_OK)
      return JNI_ERR; // attaching the JITServer Listener thread failed

   j9thread_set_name(j9thread_self(), "JITServer Metrics");

   metricsServer->serveMetricsRequests(); // Will block here till shutdown

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "Detaching JITServer metrics thread");

   vm->internalVMFunctions->DetachCurrentThread((JavaVM *) vm);
   metricsServer->getMetricsMonitor()->enter();
   metricsServer->setMetricsThread(NULL);
   metricsServer->getMetricsMonitor()->notifyAll();
   j9thread_exit((J9ThreadMonitor*)metricsServer->getMetricsMonitor()->getVMMonitor());

   return 0;
   }

void
MetricsServer::startMetricsThread(J9JavaVM *javaVM)
   {
   PORT_ACCESS_FROM_JAVAVM(javaVM);

   UDATA priority;
   priority = J9THREAD_PRIORITY_NORMAL;

   _metricsMonitor = TR::Monitor::create("JITServer-MetricsMonitor");
   if (_metricsMonitor)
      {
      // create the thread for listening to requests for metrics values
      const UDATA defaultOSStackSize = javaVM->defaultOSStackSize; //256KB stack size

      if (J9THREAD_SUCCESS != javaVM->internalVMFunctions->createJoinableThreadWithCategory(&_metricsOSThread,
                                                               defaultOSStackSize,
                                                               priority,
                                                               0,
                                                               &metricsThreadProc,
                                                               javaVM->jitConfig,
                                                               J9THREAD_CATEGORY_SYSTEM_JIT_THREAD))
         { // cannot create the MetricsServer thread
         j9tty_printf(PORTLIB, "Error: Unable to create JITServer MetricsServer Thread.\n");
         TR::Monitor::destroy(_metricsMonitor);
         _metricsMonitor = NULL;
         }
      else // must wait here until the thread gets created; otherwise an early shutdown
         { // does not know whether or not to destroy the thread
         _metricsMonitor->enter();
         while (!getAttachAttempted())
            _metricsMonitor->wait();
         _metricsMonitor->exit();
         if (!getMetricsThread())
            {
            j9tty_printf(PORTLIB, "Error: JITServer Metrics Thread attach failed.\n");
            }
         }
      }
   else
      {
      j9tty_printf(PORTLIB, "Error: Unable to create JITServer Metrics Monitor\n");
      }
   }

int32_t
MetricsServer::waitForMetricsThreadExit(J9JavaVM *javaVM)
   {
   if (NULL != _metricsOSThread)
      return omrthread_join(_metricsOSThread);
   else
      return 0;
   }

void
MetricsServer::stop()
   {
   if (getMetricsThread())
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "Will stop the metrics thread");

      _metricsMonitor->enter();
      setMetricsThreadExitFlag();
      _metricsMonitor->wait();
      _metricsMonitor->exit();
      TR::Monitor::destroy(_metricsMonitor);
      _metricsMonitor = NULL;
      }
   }


int
MetricsServer::openSocketForListening(uint32_t port)
   {
   int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
   if (sockfd < 0)
      {
      perror("can't open server socket");
      return sockfd;
      }

   // see `man 7 socket` for option explanations
   int flag = true;
   int rc = 0;
   rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof(flag));
   if (rc < 0)
      {
      perror("Can't set SO_REUSEADDR");
      return rc;
      }
   rc =setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flag, sizeof(flag));
   if (rc < 0)
      {
      perror("Can't set SO_KEEPALIVE");
      return rc;
      }

   struct sockaddr_in serv_addr;
   memset((char *)&serv_addr, 0, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   serv_addr.sin_port = htons(port);

   rc = bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
   if (rc < 0)
      {
      perror("can't bind metrics port");
      return rc; // It is possible that the port is in use
      }
   rc = listen(sockfd, SOMAXCONN);
   if (rc < 0)
      {
      perror("listen for the metrics port failed");
      return rc;
      }
   return sockfd;
   }

void
MetricsServer::reArmSocketForReading(int sockIndex)
   {
   _pfd[sockIndex].events = POLLIN;
   _pfd[sockIndex].revents = 0;
   }

void
MetricsServer::reArmSocketForWriting(int sockIndex)
   {
   _pfd[sockIndex].events = POLLOUT;
   _pfd[sockIndex].revents = 0;
   }

void
MetricsServer::closeSocket(int sockIndex)
   {
   close(_pfd[sockIndex].fd);
   _pfd[sockIndex].fd = -1;
   _pfd[sockIndex].revents = 0;
   _numActiveSockets--;
   freeSSLConnection(sockIndex);

   if (_incompleteRequests[sockIndex])
      {
      // Delete the dynamically allocated data
      _incompleteRequests[sockIndex]->~HttpGetRequest();
      TR_Memory::jitPersistentFree(_incompleteRequests[sockIndex]);
      _incompleteRequests[sockIndex] = NULL;
      }
   }

void
MetricsServer::freeSSLConnection(int sockIndex)
   {
   if (_sslConnections[sockIndex])
      {
      (*OBIO_free_all)(_sslConnections[sockIndex]);
      _sslConnections[sockIndex] = NULL;
      }
   }

void
MetricsServer::handleConnectionRequest()
   {
   static const int LISTEN_SOCKET = 0;
   TR_ASSERT_FATAL(_pfd[LISTEN_SOCKET].revents == POLLIN, "MetricsServer: Unexpected revent occurred during poll for new connection: revents=%d\n", _pfd[LISTEN_SOCKET].revents);
   struct sockaddr_in cli_addr;
   socklen_t clilen = sizeof(cli_addr);
   int sockfd = accept(_pfd[LISTEN_SOCKET].fd, (struct sockaddr *)&cli_addr, &clilen);
   if (sockfd >= 0) // success
      {
      int sockFlags = fcntl(sockfd, F_GETFL, 0);
      if (-1 == fcntl(sockfd, F_SETFL, sockFlags | O_NONBLOCK))
         {
         perror("MetricsServer error: Can't set the socket to be non-blocking");
         exit(1);
         }
      BIO *ssl = NULL;
      if (_sslCtx && !acceptOpenSSLConnection(_sslCtx, sockfd, ssl))
         {
         perror("MetricsServer error: Can't open SSL connection on socket");
         exit(1);
         }
      // Add this socket to the list (if space available)
      nfds_t k;
      for (k=1; k < 1 + MAX_CONCURRENT_REQUESTS; k++)
         {
         if (_pfd[k].fd < 0) // found empty slot
            {
            _pfd[k].fd = sockfd;
            reArmSocketForReading(k);
            _numActiveSockets++;
            // As a safety measure against memory leaks, delete any stale
            // data from a previous connection (should not be any)
            if (_incompleteRequests[k])
               {
               _incompleteRequests[k]->~HttpGetRequest();
               TR_Memory::jitPersistentFree(_incompleteRequests[k]);
               _incompleteRequests[k] = NULL;
               freeSSLConnection(k);
               }
            _sslConnections[k] = ssl;
            break;
            }
         }
      if (k >= 1 + MAX_CONCURRENT_REQUESTS)
         {
         // We could not find any empty slot for our socket. Close it
         close(sockfd);
         (*OBIO_free_all)(ssl);
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer error: could not find an available socket to process a request");
         }
      }
   else // accept() failed
      {
      if ((EAGAIN != errno) && (EWOULDBLOCK != errno))
         {
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer error: cannot accept connection: errno=%d", errno);
         }
      }
   // Prepare to wait for another connection request
   reArmSocketForReading(LISTEN_SOCKET);
   }

void
MetricsServer::handleDataForConnectedSocket(nfds_t sockIndex, MetricsDatabase &metricsDatabase)
   {
   // Check for errors first; we only expect the POLLIN or POLLOUT flag to be set
   if (_pfd[sockIndex].revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL))
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer error on socket %d revents=%d\n", _pfd[sockIndex].fd, _pfd[sockIndex].revents);
      closeSocket(sockIndex);
      }
   else if ((_pfd[sockIndex].revents & POLLIN) && (_pfd[sockIndex].events == POLLIN)) // common case
      {
      // There is data ready to be read
      HttpGetRequest httpRequest(_pfd[sockIndex].fd, _sslConnections[sockIndex]);
      HttpGetRequest *httpReq = &httpRequest;
      // Check whether we need to continue a partially read request
      if (_incompleteRequests[sockIndex])
         httpReq = _incompleteRequests[sockIndex];

      HttpGetRequest::ReturnCodes rc = httpReq->readHttpGetRequest();
      if (rc == HttpGetRequest::FULL_REQUEST_RECEIVED)
         rc = httpReq->parseHttpGetRequest();

      if (rc == HttpGetRequest::HTTP_OK) // Common case
         {
         // Save the metric data response and wait to send it to requestor
         if (httpReq->getPath() == HttpGetRequest::Path::Metrics)
            {
            httpReq->setResponse(metricsDatabase.buildMetricHttpResponse());
            }
         else // Valid, but unrecognized request type
            {
            httpReq->setResponse(std::string("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"));
            }
         if (!_incompleteRequests[sockIndex])
            {
            _incompleteRequests[sockIndex] = new (PERSISTENT_NEW) HttpGetRequest(*httpReq);
            }
         reArmSocketForWriting(sockIndex);
         }
      else if (rc == HttpGetRequest::INCOMPLETE_REQUEST)
         {
         reArmSocketForReading(sockIndex);
         // If needed, allocate a new HttpGetRequest object to maintain state
         if (!_incompleteRequests[sockIndex])
            {
            // Copy this request into the list of incomplete requests
            TR_ASSERT_FATAL(_incompleteRequests[sockIndex] == NULL, "_incompleteRequest[%u] should be NULL\n", sockIndex);
            _incompleteRequests[sockIndex] = new (PERSISTENT_NEW) HttpGetRequest(*httpReq);
            }
         }
      else // All error code come here
         {
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer experienced error code %d on socket index %u", rc, sockIndex);

         if (!_incompleteRequests[sockIndex])
            {
            _incompleteRequests[sockIndex] = new (PERSISTENT_NEW) HttpGetRequest(*httpReq);
            }
         _incompleteRequests[sockIndex]->setResponse(messageForErrorCode(rc));
         reArmSocketForWriting(sockIndex);
         }
      }
   else if ((_pfd[sockIndex].revents & POLLOUT) && (_pfd[sockIndex].events == POLLOUT))
      {
      HttpGetRequest *httpReq = _incompleteRequests[sockIndex];
      HttpGetRequest::ReturnCodes rc = httpReq->sendHttpResponse();
      if (rc == HttpGetRequest::INCOMPLETE_RESPONSE)
         {
         reArmSocketForWriting(sockIndex);
         }
      else if (rc == HttpGetRequest::FULL_RESPONSE_SENT)
         {
         closeSocket(sockIndex);
         }
      else
         {
         if (TR::Options::getVerboseOption(TR_VerboseJITServer))
            {
            TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer error. Could not send reply.");
            }
         closeSocket(sockIndex);
         }
      }
   else // Maybe POLLPRI or POLLWRBAND was seen
      {
      if (_pfd[sockIndex].events == POLLIN)
         {
         reArmSocketForReading(sockIndex);
         }
      else
         {
         reArmSocketForWriting(sockIndex);
         }
      }
   }


// Note: we close the sockets after each http request because otherwise the first 4
// agents that connect will hog the line and don't allow other agents to connect
void
MetricsServer::serveMetricsRequests()
   {
   TR::CompilationInfo *compInfo = TR::CompilationInfo::get(_jitConfig);
   TR::PersistentInfo *info = compInfo->getPersistentInfo();
   uint32_t port = info->getJITServerMetricsPort();
   int sockfd = openSocketForListening(port);
   if (sockfd < 0)
      {
      if (TR::Options::getVerboseOption(TR_VerboseJITServer))
         TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "Cannot start MetricsServer. Will continue without.");
      return;
      }

   _pfd[0].fd = sockfd; // Add the socket descriptor for incomming connection requests
   reArmSocketForReading(0);
   _numActiveSockets = 1;

   MetricsDatabase metricsDatabase(compInfo);

   if (useSSL(compInfo))
      {
      _sslCtx = createSSLContext(compInfo);
      }

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer waiting for http requests on port %u", port);

   while (!getMetricsThreadExitFlag())
      {
      // Wait on all given sockets for some activity
      int rc = poll(_pfd, _numActiveSockets, METRICS_POLL_TIMEOUT);
      if (getMetricsThreadExitFlag()) // if we are exiting, no need to check poll() status
         {
         break;
         }
      else if (0 == rc) // poll() timed out and no fd is ready
         {
         // If read operations were in progress, we must close those descriptors
         // Note that if we enable keep-alive, then we should not consider this as a timeout
         for (nfds_t i=1; i < 1 + MAX_CONCURRENT_REQUESTS; i++)
            {
            if (_pfd[i].fd >= 0)
               {
               if (_pfd[i].events == POLLIN)
                  {
                  if (TR::Options::getVerboseOption(TR_VerboseJITServer))
                     TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer: Socket %d timed-out while reading\n", _pfd[i].fd);

                  if (!_incompleteRequests[i])
                     {
                     _incompleteRequests[i] = new (PERSISTENT_NEW) HttpGetRequest(_pfd[i].fd, _sslConnections[i]);
                     }
                  _incompleteRequests[i]->setResponse(messageForErrorCode(HttpGetRequest::REQUEST_TIMEOUT));
                  reArmSocketForWriting(i);
                  }
               else
                  {
                  if (TR::Options::getVerboseOption(TR_VerboseJITServer))
                     {
                     TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "MetricsServer: Socket %d timed-out while writing\n", _pfd[i].fd);
                     }
                  closeSocket(i);
                  }
               }
            }
         continue; // Poll again waiting for a connection
         }
      else if (rc < 0) // Some error was encountered
         {
         if (errno == EINTR)
            {
            continue; // Poll again
            }
         else
            {
            perror("MetricsServer error in polling socket");
            exit(1);
            }
         }
      // At least one descriptor has incoming data
      int numSocketsChecked = 0;
      int numSocketsWithData = rc;
      for (nfds_t i = 0; i < 1 + MAX_CONCURRENT_REQUESTS && numSocketsChecked < numSocketsWithData; i++)
         {
         if (_pfd[i].fd >= 0 && _pfd[i].revents != 0) // Open socket with some data on it
            {
            numSocketsChecked++; // Increment number of active sockets checked
            if (i == 0) // First socket is used for new connection requests
               {
               handleConnectionRequest();
               }
            else // Socket 'i' has http data to read or write
               {
               handleDataForConnectedSocket(i, metricsDatabase);
               }
            }
         } // end for
      } // end while (!getMetricsThreadExitFlag())

   // The following piece of code will be executed only if the server shuts down properly
   closeSocket(0);
   if (_sslCtx)
      {
      (*OSSL_CTX_free)(_sslCtx);
      (*OEVP_cleanup)();
      }
   }

std::string
MetricsServer::messageForErrorCode(int err)
   {
   std::string response;
   switch (err)
      {
      case HttpGetRequest::MALFORMED_REQUEST:
         response = std::string("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::INVALID_PATH:
         response = std::string("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::NO_GET_REQUEST:
         response = std::string("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::REQUEST_TIMEOUT:
         response = std::string("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::REQUEST_TOO_LARGE:
         response = std::string("HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::REQUEST_URI_TOO_LONG:
         response = std::string("HTTP/1.1 414 URI Too Long\r\nConnection: close\r\n\r\n");
         break;
      case HttpGetRequest::INVALID_HTTP_PROTOCOL:
         response = std::string("HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\n\r\n");
         break;
      default:
         response = std::string("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n");
      }
   return response;
   }
