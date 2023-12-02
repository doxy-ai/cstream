#include "authorization.hpp"

#include "cpr/cpr.h"
#include "glaze/json.hpp"
#include "thirdparty/base64.hpp"
#include "thirdparty/httplib.hpp"
#include "thirdparty/sha256.hpp"
#include "thirdparty/to.hpp"

#include <algorithm>
#include <iostream>
#include <random>
#include <ranges>

namespace cstream { inline namespace auth {

	std::string generate_code_verifier(std::default_random_engine& random) {
		static std::uniform_int_distribution<unsigned char> distribution;
		// 96 bytes = 128 base64url-encoded ASCII characters
		return base64_encode(std::views::iota(0, 96) | std::views::transform([&random](auto) {
			return distribution(random);
		}));
	}

	std::string generate_code_challenge(std::string verifier) {
		SHA256 sha;
		sha.add(verifier.data(), verifier.size());
		std::string data; data.resize(32);
		sha.getHash((unsigned char*)data.data());
		return base64_encode(data);
	}


	std::string generate_state(std::default_random_engine& random) {
		return generate_code_challenge(generate_code_verifier(random));
	}
	std::string generate_state(std::time_t seed /*= std::time(nullptr)*/) {
		std::default_random_engine random(seed);
		return generate_state(random);
	}


	AuthorizationInfo generate_authorization_info(std::string clientID, std::vector<std::string> scopes, std::default_random_engine& random, std::optional<uint16_t> port /*= {}*/) {
		auto verifier = generate_code_verifier(random);
		auto state = generate_state(random);
		cpr::Session session;
		session.SetUrl({"https://api.vstream.com/oidc/auth"});
		cpr::Parameters p = {
			{"response_type", "code"},
			{"client_id", clientID},
			{"redirect_uri", "http://localhost:" + std::to_string(port.value_or(3000)) + "/"},
			{"scope", scopes_from_list(scopes)},
			{"code_challenge", generate_code_challenge(verifier)},
			{"code_challenge_method", "S256"},
			{"state", state},
		};
		if(std::ranges::find(scopes, "offline_access") != scopes.end())
			p.Add({"prompt", "consent"});
		session.SetParameters(p);
		return {verifier, state, session.GetFullRequestUrl()};
	}
	AuthorizationInfo generate_authorization_info(std::string clientID, int scopeFlags, std::default_random_engine& random, std::optional<uint16_t> port /*= {}*/) {
		return generate_authorization_info(clientID, scopes_to_strings(scopeFlags), random, port);
	}


	void open_url(std::string url) {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
		system(("start \"" + url + "\"").c_str());
#elif __APPLE__
		system(("open \"" + url + "\"").c_str());
#elif __linux__
		system(("xdg-open \"" + url + "\"").c_str());
#else
		std::cout << "Please open the following url in your web browser: " << url << std::endl;
		#warning "Unknown platform URL's won't automatically open!"
#endif
	}


	std::optional<Authorization> run_authorization_code_listening_server(std::string sessionState, std::optional<uint16_t> port /*= {}*/, bool verbose /*= true*/) {
		std::string code, refreshToken;

		httplib::Server svr;
		svr.Get("/", [&](const httplib::Request& request, httplib::Response& response) {
			auto stop_server_delayed = [&] { std::this_thread::sleep_for(std::chrono::milliseconds(100)); svr.stop(); };
			if(request.has_param("error")) {
				response.status = 401;
				response.set_content(request.get_param_value("error_description"), "text/plain");
				std::thread(stop_server_delayed).detach();
				return;
			}
			if(!request.has_param("state") || !request.has_param("code")) {
				response.status = 401;
				response.set_content("Invalid Server Response!", "text/plain");
				std::thread(stop_server_delayed).detach();
				return;
			}

			// If the state variables got changed some sort of attack is going on!
			if(request.get_param_value("state") != sessionState) {
				response.status = 401;
				response.set_content("Unauthorized!", "text/plain");
				std::thread(stop_server_delayed).detach();
				return;
			}

			code = request.get_param_value("code");
			if(request.has_param("refresh_token"))
				refreshToken = request.get_param_value("refresh_token");

			response.set_content("Code successfully recieved! Feel free to close this tab!", "text/plain");
			std::thread(stop_server_delayed).detach();
		});

		if(verbose) std::cout << "Listening for access code at: http://localhost:" << port.value_or(3000) << "/" << std::endl;
		svr.listen("localhost", port.value_or(3000));
		if(code.empty()) return {};
		return Authorization{code, refreshToken, {}};
	}


	struct TokenResponse {
		std::string access_token;
		int expires_in;
		std::string refresh_token;
		std::string scope;
		std::string token_type;

		struct glaze {
			using T = TokenResponse;
			static constexpr auto value = glz::object(&T::access_token, &T::expires_in, &T::refresh_token, &T::scope, &T::token_type);
		};
	};

	std::optional<Authorization> request_authorization_token(std::string clientID, std::string clientSecret, AuthorizationInfo info, Authorization code) {
		std::string auth = "Basic " + base64_encode(clientID + ":" + clientSecret);
		auto r = cpr::Post(cpr::Url{"https://api.vstream.com/oidc/token"}, cpr::Header{{"Authorization", auth}}, cpr::Payload{
			{"grant_type", "authorization_code"},
			{"code_verifier", info.verifier},
			{"code", code.code},
		});

		if(r.status_code == 200) {
			auto json = glz::read_json<TokenResponse>(r.text);
			if(json) {
				auto r = json.value();
				auto expires = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::seconds(r.expires_in));
				return Authorization{r.access_token, r.refresh_token, expires};
			}
		}

		return {};
	}
	std::optional<Authorization> request_authorization_token(std::string clientID, AuthorizationInfo info, Authorization code) {
		auto r = cpr::Post(cpr::Url{"https://api.vstream.com/oidc/token"}, cpr::Payload{
			{"grant_type", "authorization_code"},
			{"code_verifier", info.verifier},
			{"code", code.code},
			{"client_id", clientID}
		});

		if(r.status_code == 200) {
			auto json = glz::read_json<TokenResponse>(r.text);
			if(json) {
				auto r = json.value();
				auto expires = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::seconds(r.expires_in));
				return Authorization{r.access_token, code.refreshToken, expires};
			}
		}

		return {};
	}

	std::optional<Authorization> automated_authorization(std::string clientID, std::vector<std::string> scopes, std::optional<std::string> clientSecret /*= {}*/, std::optional<uint16_t> port /*= {}*/, bool verbose /*= true*/) {
		std::random_device randDevice;
		std::default_random_engine random(randDevice());
		auto info = generate_authorization_info(clientID, scopes, random, port);
		if(verbose) std::cout << "Waiting for authorization from: " << info.url << std::endl;
		open_url(info.url);
		auto code = run_authorization_code_listening_server(info.session_state, port, verbose);
		if(!code.has_value()) return {};

		if(clientSecret.has_value())
			return request_authorization_token(clientID, *clientSecret, info, *code);
		else return request_authorization_token(clientID, info, *code);
	}
	std::optional<Authorization> automated_authorization(std::string clientID, int scopeFlags /*= Scope::Profile*/, std::optional<std::string> clientSecret /*= {}*/, std::optional<uint16_t> port /*= {}*/, bool verbose /*= true*/) {
		return automated_authorization(clientID, scopes_to_strings(scopeFlags), clientSecret, port, verbose);
	}
}}