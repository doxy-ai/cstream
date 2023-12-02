#pragma once

#include "cpr/cprtypes.h"
#include "scope.hpp"

#include <chrono>
#include <ctime>
#include <optional>
#include <string>
#include <random>
#include <thread>

#ifdef CSTREAM_BUILD_TESTS
#include "doctest/doctest.h"
#include "tests/credentials.hpp"
#include "cpr/cpr.h"
#include <iostream>
#endif // CSTREAM_BUILD_TESTS

namespace cstream {
	/**
     * @brief Contains functions and classes for vstream OAuth2 authorization.
     */
	inline namespace oauth2 {
		/**
		* @brief Generates a random code verifier for vstream PKCE.
		* @param random The random engine.
		* @return The generated code verifier.
		*/
		std::string generate_code_verifier(std::default_random_engine& random);

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("generate_code_verifier") {
			std::default_random_engine random(7);
			CHECK(generate_code_verifier(random) == "AOtKNbqIVMDBiq-i0T1ftbINr3fszh-D7LCkk-noX1XWVSdMbUvvjrrgD0aPgmsx6A5dWKrsgypnSF1sVYidO-h13KKihIGw8GW1QJZZVGTL4BzRE2gnE_84oSR1lyPr");
			CHECK(generate_code_verifier(random).size() == 128);
			CHECK(generate_code_verifier(random) == "M7lKPKhtE8XS6uiu9QbDmbnlCSIUGxUCmvIxIjOsPnT-bKzGZWoPOs75J-yCHzWaKxNFpY57_hNpUAEBaRc77MfDb9r2zamSWWh_fpG4qqK64tj8cHz1-VsUV-G1vPTJ");
			CHECK(generate_code_verifier(random).size() == 128);
			CHECK(generate_code_verifier(random) == "Mgd4jyRSezoOCxehd866grNjnffF9raazSsQuqVui2N-HxAUWlgzoyANANXeC8RRZujLAv40pG0ILMHAP9vQUXVMQOHerX_d0dDC-LBJtlPdKdio0HfL1Ao7MgWTz6Da");
			CHECK(generate_code_verifier(random).size() == 128);
			CHECK(generate_code_verifier(random) == "oZFwBdyn-U6-8JKfMj1ybgyRx9cVTp1sUUoSXm6igYtun-XxdtX7pmegDUkH1xw9qjhFJMJOn8ED0-nE9BIuCft6RoXVtcoCHZ2_FklnxayhKO7_nrgp4yhYsmt2_HKN");
			CHECK(generate_code_verifier(random).size() == 128);
			CHECK(generate_code_verifier(random) == "XlBjA2VqzdINcZKiIh1nC0aqL_jijyhrs0hvTmMyATifpwjwFhu5rq6U8A8-Kl1TMwgngvgnhKEg6qy58LAlYnJGJmfKpK3Q2okAV_WqvNRmxFyJA48Ag31jJ38vhxkF");
			CHECK(generate_code_verifier(random).size() == 128);
		}
#endif // CSTREAM_BUILD_TESTS

		/**
		* @brief Generates a code challenge from a code verifier.
		* @param verifier The code verifier.
		* @return The generated code challenge.
		*/
		std::string generate_code_challenge(std::string_view verifier);

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("generate_code_verifier") {
			std::default_random_engine random(7);
			auto verifier = generate_code_verifier(random);
			CHECK(verifier == "AOtKNbqIVMDBiq-i0T1ftbINr3fszh-D7LCkk-noX1XWVSdMbUvvjrrgD0aPgmsx6A5dWKrsgypnSF1sVYidO-h13KKihIGw8GW1QJZZVGTL4BzRE2gnE_84oSR1lyPr");
			CHECK(generate_code_challenge(verifier) == "dG2TcdVL4lA2Sca6YdXUFTSPt4yKX6xzyJCjmZ9xamY");
		}
#endif // CSTREAM_BUILD_TESTS

		/**
		* @brief Generates a random state for authorization flow.
		* @param random The random engine.
		* @return The generated state.
		*/
		std::string generate_state(std::default_random_engine& random);
		/**
		* @brief Generates a state for authorization flow using a seed.
		* @param seed The seed for the random engine (defaults to the current system time).
		* @return The generated state.
		*/
		std::string generate_state(std::time_t seed = std::time(nullptr));

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("generate_state") {
			CHECK(generate_state(5) == "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
			CHECK(generate_state() != "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
		}
#endif // CSTREAM_BUILD_TESTS

		/**
		* @brief Represents the locally generated authorization information for vstream OAuth.
		*/
		struct AuthorizationInfo {
			std::string verifier;
			std::string session_state;
			std::string url; /// Redirect URL which when opened and authorized in a webbrowser will redirect with the authentication token!
		};
		/**
		* @brief Generates authorization information for OAuth.
		* @param clientID The OAuth client ID.
		* @param scopes The requested scopes.
		* @param random The random engine.
		* @param port The optional port for redirect URI (default = 3000).
		* @return The generated authorization information.
		*/
		AuthorizationInfo generate_authorization_info(std::string clientID, std::vector<std::string> scopes, std::default_random_engine& random, std::optional<uint16_t> port = {});
		/**
		* @brief Generates authorization information for OAuth with scope flags.
		* @param clientID The OAuth client ID.
		* @param scopeFlags The scope flags (which are converted into a list of scopes behind the scenes).
		* @param random The random engine.
		* @param port The optional port for redirect URI (default = 3000).
		* @return The generated authorization information.
		*/
		AuthorizationInfo generate_authorization_info(std::string clientID, int scopeFlags, std::default_random_engine& random, std::optional<uint16_t> port = {});

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("manual_authorization" * doctest::skip()) {
			std::default_random_engine random(7);
			auto info = generate_authorization_info(cstream::testing::credentials::clientID, Scope::ChatWrite, random);
			std::cout << info.url << std::endl;
			// open_url(info.url);
		}
#endif // CSTREAM_BUILD_TESTS

		/**
		* @brief Represents the structure of an authorization token.
		*/
		struct Authorization {
			std::string code;
			std::string refreshToken;
			std::chrono::sys_seconds expires; // Time point indicating when the token will expire!

			/**
			* @brief Returns the request header for the authorization token.
			* @return The request header.
			*/
			cpr::Header request_header() const { return cpr::Header{{"Authorization", "Bearer " + code}}; }

			std::jthread start_refresh_thread(std::string clientID, std::string clientSecret, std::chrono::milliseconds pollSleepTime = std::chrono::milliseconds(3000));
			std::jthread start_refresh_thread(std::string clientID, std::chrono::milliseconds pollSleepTime = std::chrono::milliseconds(3000)); // TODO: can you even get a refresh token without a secret?
		};
		/**
		* @brief Listens for the authorization code on a local server.
		* @note This actually spins up a simple HTTP server on a background thread, this function is the part of this process most likely to need replacement!
		* @param sessionState The session state.
		* @param port The optional port for the local server (default = 3000).
		* @param verbose Whether to print verbose messages (default = true).
		* @return Nullopt if the process failed or an Authorization object containing the obtained code and refresh token.
		*/
		std::optional<Authorization> run_authorization_code_listening_server(std::string_view sessionState, std::optional<uint16_t> port = {}, bool verbose = true);

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("run_authorization_code_listening_server (No Refresh Token)") {
			std::string code, refresh;
			auto thread = std::thread([&]{
				auto r = run_authorization_code_listening_server("bob");
				code = r->code;
				refresh = r->refreshToken;
			});

			std::this_thread::sleep_for(std::chrono::milliseconds(100));

			auto r = cpr::Get(cpr::Url{"http://localhost:3000/"}, cpr::Parameters{
				{"code", "12345"},
				{"state", "bob"}
			});

			thread.join();
			CHECK(r.status_code == 200);
			CHECK(code == "12345");
			CHECK(refresh.empty() == true);
		}

		TEST_CASE("run_authorization_code_listening_server") {
			std::string code, refresh;
			auto thread = std::thread([&]{
				auto r = run_authorization_code_listening_server("bob");
				code = r->code;
				refresh = r->refreshToken;
			});

			std::this_thread::sleep_for(std::chrono::milliseconds(100));

			auto r = cpr::Get(cpr::Url{"http://localhost:3000/"}, cpr::Parameters{
				{"code", "12345"},
				{"refresh_token", "54321"},
				{"state", "bob"}
			});

			thread.join();
			CHECK(r.status_code == 200);
			CHECK(code == "12345");
			CHECK(refresh == "54321");
		}
#endif // CSTREAM_BUILD_TESTS

		/**
		* @brief Requests an authorization token from the vstream OAuth token endpoint using an already received authorization code.
		* @param clientID The OAuth client ID.
		* @param clientSecret The OAuth client secret.
		* @param info The authorization information.
		* @param code The obtained authorization code.
		* @return An optional Authorization object containing the access token and its details.
		*/
		std::optional<Authorization> request_authorization_token(std::string clientID, std::string clientSecret, AuthorizationInfo info, Authorization code);
		/**
		* @brief Requests an authorization token from the vstream OAuth token endpoint using authorization code.
		* @note This version is for public clients which weren't assigned a client secret!
		* @param clientID The OAuth client ID.
		* @param info The authorization information.
		* @param code The obtained authorization code.
		* @return An optional Authorization object containing the access token and its details.
		*/
		std::optional<Authorization> request_authorization_token(std::string clientID, AuthorizationInfo info, Authorization code);

		/**
		* @brief Automates the entire OAuth authorization process by composing all of the other functions in this namespace.
		* @param clientID The OAuth client ID.
		* @param scopes The requested list of scopes.
		* @param clientSecret The optional OAuth client secret.
		* @param port The optional port for redirect URI (default = 3000).
		* @param verbose Whether to print verbose messages (default = true).
		* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
		*/
		std::optional<Authorization> automated_authorization(std::string clientID, std::vector<std::string> scopes, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true);
		/**
		* @brief Automates the entire OAuth authorization process with scope flags.
		* @param clientID The OAuth client ID.
		* @param scopeFlags The scope flags (which are converted into a list of scopes behind the scenes).
		* @param clientSecret The optional OAuth client secret.
		* @param port The optional port for redirect URI (default = 3000).
		* @param verbose Whether to print verbose messages (default = true).
		* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
		*/
		std::optional<Authorization> automated_authorization(std::string clientID, int scopeFlags = Scope::Profile, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true);
		/**
		* @brief Automates the entire OAuth authorization process by composing all of the other functions in this namespace.
		* @param clientID The OAuth client ID.
		* @param clientSecret The OAuth client secret.
		* @note This version is more ergonomic for applications which have both and ID and a secret
		* @param scopes The requested list of scopes.
		* @param port The optional port for redirect URI (default = 3000).
		* @param verbose Whether to print verbose messages (default = true).
		* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
		*/
		inline std::optional<Authorization> automated_authorization(std::string clientID, std::string clientSecret, std::vector<std::string> scopes, std::optional<uint16_t> port = {}, bool verbose = true) {
			return automated_authorization(clientID, scopes, clientSecret, port, verbose);
		}
		/**
		* @brief Automates the entire OAuth authorization process with scope flags.
		* @param clientID The OAuth client ID.
		* @param clientSecret The OAuth client secret.
		* @note This version is more ergonomic for applications which have both and ID and a secret
		* @param scopeFlags The scope flags (which are converted into a list of scopes behind the scenes).
		* @param port The optional port for redirect URI (default = 3000).
		* @param verbose Whether to print verbose messages (default = true).
		* @return Nullopt if something went wrong, otherwise an Authorization object containing the access token and its details.
		*/
		inline std::optional<Authorization> automated_authorization(std::string clientID, std::string clientSecret, int scopeFlags = Scope::Profile, std::optional<uint16_t> port = {}, bool verbose = true) {
			return automated_authorization(clientID, scopeFlags, clientSecret, port, verbose);
		}

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("manual_automated_authorization" * doctest::skip()) {
			// TODO: Test public token authorization!
			SUBCASE("chat:write"){
				auto auth = automated_authorization(cstream::testing::credentials::clientID, {"chat:write"}, cstream::testing::credentials::clientSecret);
				CHECK(auth.has_value() == true);
				CHECK(auth->code.empty() == false);
				CHECK(auth->refreshToken.empty() == true);
			}

			SUBCASE("offline_access"){
				auto auth = automated_authorization(cstream::testing::credentials::clientID, Scope::ChatWrite | Scope::OfflineAccess, cstream::testing::credentials::clientSecret);
				CHECK(auth.has_value() == true);
				CHECK(auth->code.empty() == false);
				CHECK(auth->refreshToken.empty() == false);
			}
		}
#endif // CSTREAM_BUILD_TESTS
	}
}