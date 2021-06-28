/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

#include <fstream>
#include <sstream>

std::string loadFile(const std::string& filename)
{
	std::ifstream file(filename);
	if (file.is_open() == false)
		throw std::runtime_error(std::string("file not found: ") + filename);

	std::ostringstream ss;
	std::string line;
	while (std::getline(file, line))
		ss << line << std::endl;

	if (file.bad())
		throw std::runtime_error(std::string("something went wrong while reading file: ") + filename);

	return std::move(ss.str());
}


#include "mbedtls/config.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pem.h"
#include "mbedtls/base64.h"


#include "ra_tls.h"
#include "sgx_arch.h"

#include <dlfcn.h>

// #define CERT_SUBJECT_NAME_VALUES  "CN=RATLS,O=GrapheneDevelopers,C=US"
// #define CERT_TIMESTAMP_NOT_BEFORE_DEFAULT "20010101000000"
// #define CERT_TIMESTAMP_NOT_AFTER_DEFAULT  "20301231235959"

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

/* RA-TLS: on server, only need ra_tls_create_key_and_crt() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_f)(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  // Set up ssl server certs
  int ret;
  char* error;
  
  void* ra_tls_attest_lib     = NULL;
  ra_tls_create_key_and_crt_f = NULL;
  
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;

  mbedtls_x509_crt_init(&srvcert);
  mbedtls_pk_init(&pkey);
  
  ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
  if (!ra_tls_attest_lib) {
      throw std::runtime_error(std::string("User requested RA-TLS attestation but cannot find lib\n"));
  }

  ra_tls_create_key_and_crt_f = reinterpret_cast<int (*)(mbedtls_pk_context*, mbedtls_x509_crt*)> (dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt"));
  if ((error = dlerror()) != NULL) {
    throw std::runtime_error(std::string(std::string(error)+"\n"));
    return;
  }

  if (ra_tls_attest_lib) {
      printf("\n  . Creating the RA-TLS server cert and key...");
      fflush(stdout);
      ret = (*ra_tls_create_key_and_crt_f)(&pkey, &srvcert);
      if (ret != 0) {
          throw std::runtime_error(std::string("failed\n  !  ra_tls_create_key_and_crt returned %d\n\n", ret));
      }
      printf(" ok\n");
      fflush(stdout);
    }

  unsigned char private_key_pem[16000];
  unsigned char *c = private_key_pem;
  if( ( ret = mbedtls_pk_write_key_pem( &pkey, private_key_pem, 16000 ) ) != 0 )
      throw std::runtime_error(std::string("something went wrong while extracting private key"));

  unsigned char cert_pem[16000];
  size_t olen;
  if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CRT, PEM_END_CRT,
                                        srvcert.raw.p, srvcert.raw.len,
                                        cert_pem, 16000, &olen ) ) != 0 );

  std::cout << private_key_pem << std::endl;
  std::cout << cert_pem << std::endl;

  std::string s_private_key_pem((char*) private_key_pem);
  std::string s_cert_pem((char*) cert_pem);

	grpc::SslServerCredentialsOptions::PemKeyCertPair pair;  
  pair.private_key = s_private_key_pem;
  pair.cert_chain = s_cert_pem;

  grpc::SslServerCredentialsOptions sslopt;
  sslopt.pem_root_certs="";
  sslopt.pem_key_cert_pairs.push_back(pair);

  // https://cpp.hotexamples.com/examples/-/ServerBuilder/-/cpp-serverbuilder-class-examples.html
	// sslopt.pem_root_certs = loadFile("ca.cert.pem");
	// pair.private_key = loadFile("server.key.pem");
	// pair.cert_chain = loadFile("server.cert.pem");
	// sslopt.pem_key_cert_pairs.emplace_back(std::move(pair));

  auto channel_creds = grpc::SslServerCredentials(sslopt);
  
  // Listen on the given address with ssl authentication mechanism.
  ServerBuilder builder;
  builder.AddListeningPort(server_address, channel_creds);
  // builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  RunServer();

  return 0;
}
