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
#include <fstream>

#include <grpcpp/grpcpp.h>
#include "grpc/grpc_security_constants.h"
#include <grpc/grpc_security.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

#include "grpc/support/string_util.h"

#include <dlfcn.h>
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#define mbedtls_printf printf

/* RA-TLS: on client, only need to register ra_tls_verify_callback() for cert verification */
int (*ra_tls_verify_callback_f)(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}

/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
                                  const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave &&
            memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
        return -1;

    if (g_verify_mrsigner &&
            memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
        return -1;

    if (g_verify_isv_prod_id &&
            memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
        return -1;

    if (g_verify_isv_svn &&
            memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
        return -1;

    return 0;
}

class TlsSGXServerAuthorizationCheck
    : public grpc::experimental::TlsServerAuthorizationCheckInterface {
  int Schedule(grpc::experimental::TlsServerAuthorizationCheckArg* arg) override {
    GPR_ASSERT(arg != nullptr);

    int ret;

    void* dummy_data;
    mbedtls_x509_crt peer_cert;  
    mbedtls_x509_crt_init(&peer_cert);
    auto peer_cert_buf = arg->peer_cert();

    char cert_pem[16000];
    peer_cert_buf.copy(cert_pem, peer_cert_buf.length(), 0);

    std::cout << peer_cert_buf.length() << std::endl;
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&peer_cert, (const unsigned char*) cert_pem , 16000);
    if (ret != 0) {
      throw std::runtime_error(std::string("something went wrong while parsing peer certificate"));
    }
    
    ret = (*ra_tls_verify_callback_f)(dummy_data, &peer_cert, 0, NULL);
    if (ret != 0) {
      throw std::runtime_error(std::string("something went wrong while verifying quote"));
    }

    arg->set_success(1);
    // auto peer_cert = arg->peer_cert();
    // std::cout << peer_cert << std::endl;
    // fflush(stdout);
    arg->set_status(GRPC_STATUS_OK);
    return 0;
  }

  void Cancel(grpc::experimental::TlsServerAuthorizationCheckArg* arg) override {
    GPR_ASSERT(arg != nullptr);
    std::cout << "now at Cancel" << std::endl;
    fflush(stdout);
    arg->set_status(GRPC_STATUS_PERMISSION_DENIED);
    arg->set_error_details("cancelled");
  }
};

int main(int argc, char** argv) {
    void* ra_tls_verify_lib           = NULL;
    char* error;

    void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
      if (!helper_sgx_urts_lib) {
          mbedtls_printf("%s\n", dlerror());
          mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
                          " libsgx_urts.so lib\n");
          return 1;
      }

    ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
      if (!ra_tls_verify_lib) {
          mbedtls_printf("%s\n", dlerror());
          mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
          return 1;
      }

    if (ra_tls_verify_lib) {
      ra_tls_verify_callback_f = reinterpret_cast<int (*)(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)> (dlsym(ra_tls_verify_lib, "ra_tls_verify_callback"));
      if ((error = dlerror()) != NULL) {
          mbedtls_printf("%s\n", error);
          return 1;
      }

      ra_tls_set_measurement_callback_f = reinterpret_cast<void (*)(int (*f_cb)(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn))> (dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback"));
      if ((error = dlerror()) != NULL) {
          mbedtls_printf("%s\n", error);
          return 1;
      }
    }

    if (argc > 2 && ra_tls_verify_lib) {
        if (argc != 6) {
            mbedtls_printf("USAGE: %s %s <expected mrenclave> <expected mrsigner>"
                           " <expected isv_prod_id> <expected isv_svn>\n"
                           "       (first two in hex, last two as decimal; set to 0 to ignore)\n",
                           argv[0], argv[1]);
            return 1;
        }

        mbedtls_printf("[ using our own SGX-measurement verification callback"
                       " (via command line options) ]\n");

        g_verify_mrenclave   = true;
        g_verify_mrsigner    = true;
        g_verify_isv_prod_id = true;
        g_verify_isv_svn     = true;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

        if (!strcmp(argv[2], "0")) {
            mbedtls_printf("  - ignoring MRENCLAVE\n");
            g_verify_mrenclave = false;
        } else if (parse_hex(argv[2], g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
            mbedtls_printf("Cannot parse MRENCLAVE!\n");
            return 1;
        }

        if (!strcmp(argv[3], "0")) {
            mbedtls_printf("  - ignoring MRSIGNER\n");
            g_verify_mrsigner = false;
        } else if (parse_hex(argv[3], g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
            mbedtls_printf("Cannot parse MRSIGNER!\n");
            return 1;
        }

        if (!strcmp(argv[4], "0")) {
            mbedtls_printf("  - ignoring ISV_PROD_ID\n");
            g_verify_isv_prod_id = false;
        } else {
            errno = 0;
            uint16_t isv_prod_id = (uint16_t)strtoul(argv[4], NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_PROD_ID!\n");
                return 1;
            }
            memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
        }

        if (!strcmp(argv[5], "0")) {
            mbedtls_printf("  - ignoring ISV_SVN\n");
            g_verify_isv_svn = false;
        } else {
            errno = 0;
            uint16_t isv_svn = (uint16_t)strtoul(argv[5], NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_SVN\n");
                return 1;
            }
            memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
        }
    } else if (ra_tls_verify_lib) {
        mbedtls_printf("[ using default SGX-measurement verification callback"
                       " (via RA_TLS_* environment variables) ]\n");
        (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */
    } else {
        mbedtls_printf("[ using normal TLS flows ]\n");
    }


  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.

  std::string target_str;
  std::string arg_str("--target");
  if (argc > 1) {
    std::string arg_val = argv[1];
    size_t start_pos = arg_val.find(arg_str);
    if (start_pos != std::string::npos) {
      start_pos += arg_str.size();
      if (arg_val[start_pos] == '=') {
        target_str = arg_val.substr(start_pos + 1);
      } else {
        std::cout << "The only correct argument syntax is --target="
                  << std::endl;
        return 0;
      }
    } else {
      std::cout << "The only acceptable argument is --target=" << std::endl;
      return 0;
    }
  } else {
    target_str = "localhost:50051";
  }

  // auto ssl_opts = grpc::SslCredentialsOptions();
  // std::ifstream ifs("server.crt");
  // std::string content( (std::istreambuf_iterator<char>(ifs)),
  //                      (std::istreambuf_iterator<char>()));

  // ssl_opts.pem_root_certs=content;
  
  // auto certificate_provider =
  //     std::make_shared<grpc::experimental::StaticDataCertificateProvider>(content);
  // GPR_ASSERT(certificate_provider != nullptr);
  // GPR_ASSERT(certificate_provider->c_provider() != nullptr);
  grpc::experimental::TlsChannelCredentialsOptions options;
  // options.set_certificate_provider(certificate_provider);
  // options.watch_root_certs();
  // options.set_root_cert_name("root_cert_name");
  
  options.set_server_verification_option(GRPC_TLS_SKIP_ALL_SERVER_VERIFICATION);

  auto sgx_server_authorization_check = std::make_shared<TlsSGXServerAuthorizationCheck>();
  auto server_authorization_check_config = std::make_shared<grpc::experimental::TlsServerAuthorizationCheckConfig>(
          sgx_server_authorization_check);
  options.set_server_authorization_check_config(server_authorization_check_config);

  auto channel_credentials = grpc::experimental::TlsCredentials(options);
  GPR_ASSERT(channel_credentials.get() != nullptr);

  GreeterClient greeter(
      grpc::CreateChannel(target_str, channel_credentials));

       
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}

  // auto chan_opts = grpc::experimental::TlsChannelCredentialsOptions();
  // chan_opts.set_server_verification_option(GRPC_TLS_SKIP_ALL_SERVER_VERIFICATION);
  // auto channel_creds = grpc::experimental::TlsCredentials(chan_opts); 


  // Establish a channel pointing at the TLS server. Since the gRPC runtime is
  // lazy, this won't necessarily establish a connection yet.
  // grpc_arg ssl_name_override = {
  //     GRPC_ARG_STRING,
  //     const_cast<char*>(GRPC_SSL_TARGET_NAME_OVERRIDE_ARG),
  //     {const_cast<char*>("foo.test.google.fr")}};
  // grpc_channel_args grpc_args;
  // grpc_args.num_args = 1;
  // grpc_args.args = &ssl_name_override;
  // grpc_channel* channel = grpc_secure_channel_create(ssl_creds, target_str,
  //                                                    &grpc_args, nullptr);
  // auto grpc_channel_creds = grpc_ssl_credentials_create_ex(content.c_str(), NULL, NULL, NULL);

  // GreeterClient greeter(channel);

  // auto channel_creds = grpc::SslCredentials(ssl_opts);
  // auto channel_args = grpc::ChannelArguments();
  // channel_args.SetSslTargetNameOverride("RATLS");
  // GreeterClient greeter(
  //     grpc::CreateCustomChannel(target_str, channel_credentials, channel_args));
