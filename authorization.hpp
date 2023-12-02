#pragma once

#include "scope.hpp"

#include <chrono>
#include <ctime>
#include <optional>
#include <string>
#include <random>

#ifdef CSTREAM_BUILD_TESTS
#include "doctest/doctest.h"
#include "tests/credentials.hpp"
#include "cpr/cpr.h"
#include <iostream>
#endif // CSTREAM_BUILD_TESTS

namespace cstream {
	inline namespace auth {
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

		std::string generate_code_challenge(std::string verifier);

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("generate_code_verifier") {
			std::default_random_engine random(7);
			auto verifier = generate_code_verifier(random);
			CHECK(verifier == "AOtKNbqIVMDBiq-i0T1ftbINr3fszh-D7LCkk-noX1XWVSdMbUvvjrrgD0aPgmsx6A5dWKrsgypnSF1sVYidO-h13KKihIGw8GW1QJZZVGTL4BzRE2gnE_84oSR1lyPr");
			CHECK(generate_code_challenge(verifier) == "dG2TcdVL4lA2Sca6YdXUFTSPt4yKX6xzyJCjmZ9xamY");
		}
#endif // CSTREAM_BUILD_TESTS

		std::string generate_state(std::default_random_engine& random);
		std::string generate_state(std::time_t seed = std::time(nullptr));

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("generate_state") {
			CHECK(generate_state(5) == "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
			CHECK(generate_state() != "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
		}
#endif // CSTREAM_BUILD_TESTS

		struct AuthorizationInfo {
			std::string verifier;
			std::string session_state;
			std::string url;
		};
		AuthorizationInfo generate_authorization_info(std::string clientID, std::vector<std::string> scopes, std::default_random_engine& random, std::optional<uint16_t> port = {});
		AuthorizationInfo generate_authorization_info(std::string clientID, int scopeFlags, std::default_random_engine& random, std::optional<uint16_t> port = {});

#ifdef CSTREAM_BUILD_TESTS
		TEST_CASE("manual_authorization" * doctest::skip()) {
			std::default_random_engine random(7);
			auto info = generate_authorization_info(cstream::testing::credentials::clientID, Scope::ChatWrite, random);
			std::cout << info.url << std::endl;
			// open_url(info.url);
		}
#endif // CSTREAM_BUILD_TESTS

		struct Authorization {
			std::string code;
			std::string refreshToken;
			std::chrono::sys_seconds expires;
		};
		std::optional<Authorization> run_authorization_code_listening_server(std::string sessionState, std::optional<uint16_t> port = {}, bool verbose = true);

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

		std::optional<Authorization> request_authorization_token(std::string clientID, std::string clientSecret, AuthorizationInfo info, Authorization code);
		std::optional<Authorization> request_authorization_token(std::string clientID, AuthorizationInfo info, Authorization code);

		std::optional<Authorization> automated_authorization(std::string clientID, std::vector<std::string> scopes, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true);
		std::optional<Authorization> automated_authorization(std::string clientID, int scopeFlags = Scope::Profile, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true);

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