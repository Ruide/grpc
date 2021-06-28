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

int main(int argc, char** argv) {
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

  auto ssl_opts = grpc::SslCredentialsOptions();
  std::ifstream ifs("server.crt");
  std::string content( (std::istreambuf_iterator<char>(ifs)),
                       (std::istreambuf_iterator<char>()));

  ssl_opts.pem_root_certs=content;
  
  auto certificate_provider =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(content);
  GPR_ASSERT(certificate_provider != nullptr);
  GPR_ASSERT(certificate_provider->c_provider() != nullptr);
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(certificate_provider);
  options.watch_root_certs();
  options.set_root_cert_name("root_cert_name");
  options.set_server_verification_option(GRPC_TLS_SERVER_VERIFICATION);
  auto channel_credentials = grpc::experimental::TlsCredentials(options);

  // auto channel_creds = grpc::SslCredentials(ssl_opts);
  auto channel_args = grpc::ChannelArguments();
  channel_args.SetSslTargetNameOverride("RATLS");

  // GreeterClient greeter(
      // grpc::CreateChannel(target_str, channel_creds));

  GreeterClient greeter(
      grpc::CreateCustomChannel(target_str, channel_credentials, channel_args));
      
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}

  // auto chan_opts = grpc::experimental::TlsChannelCredentialsOptions();
  // chan_opts.set_server_verification_option(GRPC_TLS_SGX_SERVER_VERIFICATION);
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