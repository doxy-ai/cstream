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

namespace cstream { inline namespace oauth2 {

	/**
	* @brief Generates a random code verifier for vstream PKCE.
	* @param random The random engine.
	* @return The generated code verifier.
	*/
	std::string generate_code_verifier(std::default_random_engine& random) {
		static std::uniform_int_distribution<unsigned char> distribution;
		// 96 bytes = 128 base64url-encoded ASCII characters
		return base64_encode(std::views::iota(0, 96) | std::views::transform([&random](auto) {
			return distribution(random);
		}));
	}

	/**
	* @brief Generates a code challenge from a code verifier.
	* @param verifier The code verifier.
	* @return The generated code challenge.
	*/
	std::string generate_code_challenge(std::string_view verifier) {
		SHA256 sha;
		sha.add(verifier.data(), verifier.size());
		std::string data; data.resize(32);
		sha.getHash((unsigned char*)data.data());
		return base64_encode(data);
	}


	/**
	* @brief Generates a random state for authorization flow.
	* @param random The random engine.
	* @return The generated state.
	*/
	std::string generate_state(std::default_random_engine& random) {
		return generate_code_challenge(generate_code_verifier(random));
	}
	/**
	* @brief Generates a state for authorization flow using a seed.
	* @param seed The seed for the random engine (defaults to the current system time).
	* @return The generated state.
	*/
	std::string generate_state(std::time_t seed /*= std::time(nullptr)*/) {
		std::default_random_engine random(seed);
		return generate_state(random);
	}

	/**
	* @brief Generates authorization information for OAuth.
	* @param clientID The OAuth client ID.
	* @param scopes The requested list of scopes.
	* @param random The random engine.
	* @param port The optional port for redirect URI (default = 3000).
	* @return The generated authorization information.
	*/
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
	/**
	* @brief Generates authorization information for OAuth with scope flags.
	* @param clientID The OAuth client ID.
	* @param scopeFlags The scope flags (which are converted into a list of scopes behind the scenes).
	* @param random The random engine.
	* @param port The optional port for redirect URI (default = 3000).
	* @return The generated authorization information.
	*/
	AuthorizationInfo generate_authorization_info(std::string clientID, int scopeFlags, std::default_random_engine& random, std::optional<uint16_t> port /*= {}*/) {
		return generate_authorization_info(clientID, scopes_to_strings(scopeFlags), random, port);
	}


	/**
	* @brief Opens the given URL in a web browser based on the platform.
	* @param url The URL to open.
	*/
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

	/**
	* @brief Listens for the authorization code on a local server.
	* @note This actually spins up a simple HTTP server on a background thread, this function is the part of this process most likely to need replacement!
	* @param sessionState The session state.
	* @param port The optional port for the local server (default = 3000).
	* @param verbose Whether to print verbose messages (default = true).
	* @return Nullopt if the process failed or an Authorization object containing the obtained code and refresh token.
	*/
	std::optional<Authorization> run_authorization_code_listening_server(std::string_view sessionState, std::optional<uint16_t> port /*= {}*/, bool verbose /*= true*/) {
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

			response.set_content("Code successfully received! Feel free to close this tab!", "text/plain");
			std::thread(stop_server_delayed).detach();
		});

		if(verbose) std::cout << "Listening for access code at: http://localhost:" << port.value_or(3000) << "/" << std::endl;
		svr.listen("localhost", port.value_or(3000));
		if(code.empty()) return {};
		return Authorization{code, refreshToken, {}};
	}


	/**
	* @brief Represents the structure of a token response from the OAuth token endpoint.
	* @note JSON response object, that is only used internally
	*/
	struct TokenResponse {
		std::string access_token;
		int expires_in;
		std::string refresh_token;
		std::string scope;
		std::string token_type;

		/**
		* @brief Glaze serialization for TokenResponse.
		*/
		struct glaze {
			using T = TokenResponse;
			static constexpr auto value = glz::object(
				"access_token", &T::access_token, 
				"expires_in", &T::expires_in, 
				"refresh_token", &T::refresh_token, 
				"scope", &T::scope, 
				"token_type", &T::token_type
			);
		};
	};

	/**
	* @brief Requests an authorization token from the vstream OAuth token endpoint using an already received authorization code.
	* @param clientID The OAuth client ID.
	* @param clientSecret The OAuth client secret.
	* @param info The authorization information.
	* @param code The obtained authorization code.
	* @return An optional Authorization object containing the access token and its details.
	*/
	std::optional<Authorization> request_authorization_token(std::string clientID, std::string clientSecret, AuthorizationInfo info, Authorization code) {
		std::string auth = "Basic " + base64_encode(clientID + ":" + clientSecret);
		auto r = cpr::Post(cpr::Url{"https://api.vstream.com/oidc/token"}, cpr::Header{{"Authorization", auth}}, cpr::Payload{
			{"grant_type", "authorization_code"},
			{"code_verifier", info.verifier},
			{"code", code.code},
		});

		if(r.status_code == 200) {
			glz::context ctx;
			TokenResponse json;
			if(glz::read<glz::opts{.error_on_unknown_keys = false}>(json, r.text, ctx) == glz::error_code::none) {
				auto& r = json;
				auto expires = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::seconds(r.expires_in));
				return Authorization{r.access_token, r.refresh_token, expires};
			}
		}

		return {};
	}
	/**
	* @brief Requests an authorization token from the vstream OAuth token endpoint using authorization code.
	* @note This version is for public clients which weren't assigned a client secret!
	* @param clientID The OAuth client ID.
	* @param info The authorization information.
	* @param code The obtained authorization code.
	* @return An optional Authorization object containing the access token and its details.
	*/
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

	/**
	* @brief Automates the entire OAuth authorization process by composing all of the other functions in this namespace.
	* @param clientID The OAuth client ID.
	* @param scopes The requested list of scopes.
	* @param clientSecret The optional OAuth client secret.
	* @param port The optional port for redirect URI (default = 3000).
	* @param verbose Whether to print verbose messages (default = true).
	* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
	*/
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
	/**
	* @brief Automates the entire OAuth authorization process with scope flags.
	* @param clientID The OAuth client ID.
	* @param scopeFlags The scope flags (which are converted into a list of scopes behind the scenes).
	* @param clientSecret The optional OAuth client secret.
	* @param port The optional port for redirect URI (default = 3000).
	* @param verbose Whether to print verbose messages (default = true).
	* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
	*/
	std::optional<Authorization> automated_authorization(std::string clientID, int scopeFlags /*= Scope::Profile*/, std::optional<std::string> clientSecret /*= {}*/, std::optional<uint16_t> port /*= {}*/, bool verbose /*= true*/) {
		return automated_authorization(clientID, scopes_to_strings(scopeFlags), clientSecret, port, verbose);
	}



	std::jthread Authorization::start_refresh_thread(std::string clientID, std::string clientSecret, std::chrono::milliseconds pollSleepTime /*= std::chrono::milliseconds(3000)*/) {
		return std::jthread([=, this](std::stop_token t) {
			while(!t.stop_requested()) {
				if(std::chrono::system_clock::now() < expires - pollSleepTime) {
					std::this_thread::sleep_for(pollSleepTime);
					continue;
				}

				std::string auth = "Basic " + base64_encode(clientID + ":" + clientSecret);
				auto r = cpr::Post(cpr::Url{"https://api.vstream.com/oidc/token"}, cpr::Header{{"Authorization", auth}}, cpr::Payload{
					{"grant_type", "refresh_token"},
					{"refresh_token", refreshToken},
				});

				if(r.status_code == 200) {
					auto json = glz::read_json<TokenResponse>(r.text);
					if(json) {
						auto r = json.value();
						expires = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::seconds(r.expires_in));
						code = r.access_token;
						refreshToken = r.refresh_token;
					}
				}
			}
		});
	}
	std::jthread Authorization::start_refresh_thread(std::string clientID, std::chrono::milliseconds pollSleepTime /*= std::chrono::milliseconds(3000)*/) {
		return std::jthread([=, this](std::stop_token t) {
			while(!t.stop_requested()) {
				if(std::chrono::system_clock::now() < expires - pollSleepTime) {
					std::this_thread::sleep_for(pollSleepTime);
					continue;
				}

				auto r = cpr::Post(cpr::Url{"https://api.vstream.com/oidc/token"}, cpr::Payload{
					{"grant_type", "refresh_token"},
					{"refresh_token", refreshToken},
					{"client_id", clientID},
				});

				if(r.status_code == 200) {
					auto json = glz::read_json<TokenResponse>(r.text);
					if(json) {
						auto r = json.value();
						expires = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now() + std::chrono::seconds(r.expires_in));
						code = r.access_token;
						refreshToken = r.refresh_token;
					}
				}
			}
		});
	}
}} // namespace cstream::oauth2