#include <iostream>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include "cpr/cpr.h"

#include "tests/credentials.hpp"
#include "thirdparty/base64.hpp"
#include "thirdparty/sha256.hpp"
#include "thirdparty/to.hpp"
#include <random>

std::string generate_code_verifier(std::default_random_engine& random) {
	static std::uniform_int_distribution<unsigned char> distribution;
	// 96 bytes = 128 base64url-encoded ASCII characters
	return base64_encode(std::views::iota(0, 96) | std::views::transform([&random](auto) {
		return distribution(random);
	}));
}

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

std::string generate_code_challenge(std::string verifier) {
	SHA256 sha;
	sha.add(verifier.data(), verifier.size());
	std::string data; data.resize(32);
	sha.getHash((unsigned char*)data.data());
	return base64_encode(data);
}

TEST_CASE("generate_code_verifier") {
	std::default_random_engine random(7);
	auto verifier = generate_code_verifier(random);
	CHECK(verifier == "AOtKNbqIVMDBiq-i0T1ftbINr3fszh-D7LCkk-noX1XWVSdMbUvvjrrgD0aPgmsx6A5dWKrsgypnSF1sVYidO-h13KKihIGw8GW1QJZZVGTL4BzRE2gnE_84oSR1lyPr");
	CHECK(generate_code_challenge(verifier) == "dG2TcdVL4lA2Sca6YdXUFTSPt4yKX6xzyJCjmZ9xamY");
}



std::string generate_state(std::default_random_engine& random) {
	return generate_code_challenge(generate_code_verifier(random));
}
std::string generate_state(time_t seed = time(nullptr)) {
	std::default_random_engine random(seed);
	return generate_state(random);
}

TEST_CASE("generate_state") {
	CHECK(generate_state(5) == "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
	CHECK(generate_state() != "iG4YrqiaSWc85TLtycskLHu06crSEKkEPbnO4SXEr3o");
}




enum Scope {
	ChatWrite = 1 << 1,             // chat:write
	BillingPrivateRead = 1 << 2,    // billing:private:read
	OfflineAccess = 1 << 3,         // offline_access
	OpenID = 1 << 4,                // openid
	Profile = 1 << 5,               // profile
	VideoPrivateRead = 1 << 6,      // video:private:read
};

std::vector<std::string> scopes_to_strings(int scopeFlags) {
	std::vector<std::string> out;
	if(scopeFlags & ChatWrite) out.emplace_back("chat:write");
	if(scopeFlags & BillingPrivateRead) out.emplace_back("billing:private:read");
	if(scopeFlags & OfflineAccess) out.emplace_back("offline_access");
	if(scopeFlags & OpenID) out.emplace_back("openid");
	if(scopeFlags & Profile) out.emplace_back("profile");
	if(scopeFlags & VideoPrivateRead) out.emplace_back("video:private:read");
	return out;
}

TEST_CASE("scopes_to_strings") {
	CHECK(scopes_to_strings(Scope::ChatWrite) == std::vector<std::string>{"chat:write"});
	CHECK(scopes_to_strings(Scope::BillingPrivateRead) == std::vector<std::string>{"billing:private:read"});
	CHECK(scopes_to_strings(Scope::OfflineAccess) == std::vector<std::string>{"offline_access"});
	CHECK(scopes_to_strings(Scope::OpenID) == std::vector<std::string>{"openid"});
	CHECK(scopes_to_strings(Scope::Profile) == std::vector<std::string>{"profile"});
	CHECK(scopes_to_strings(Scope::VideoPrivateRead) == std::vector<std::string>{"video:private:read"});

	CHECK(scopes_to_strings(Scope::ChatWrite | Scope::VideoPrivateRead) == std::vector<std::string>{"chat:write", "video:private:read"});
}

std::string scopes_from_list(std::vector<std::string> scopes) {
	if(scopes.empty()) return "";
	return std::accumulate(std::next(scopes.begin()), scopes.end(), scopes[0],
		[](std::string a, std::string b) {
			return a + " " + b;
		}
	);
}
std::string scopes_from_list(int scopeFlags) {
	return scopes_from_list(scopes_to_strings(scopeFlags));
}





struct AuthorizationInfo {
	std::string verifier;
	std::string session_state;
	std::string url;
};

AuthorizationInfo generate_authorization_info(std::string clientID, std::vector<std::string> scopes, std::default_random_engine& random, std::optional<uint16_t> port = {}) {
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
AuthorizationInfo generate_authorization_info(std::string clientID, int scopeFlags, std::default_random_engine& random, std::optional<uint16_t> port = {}) {
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


TEST_CASE("manual_authorization" * doctest::skip()) {
	std::default_random_engine random(7);
	auto info = generate_authorization_info(cstream::testing::credentials::clidentID, Scope::ChatWrite, random);
	std::cout << info.url << std::endl;
	// open_url(info.url);
}

#include "thirdparty/httplib.hpp"

struct Authorization {
	std::string code;
	std::string refreshToken;
	std::chrono::sys_seconds expires;
};
std::optional<Authorization> run_authorization_code_listening_server(std::string sessionState, std::optional<uint16_t> port = {}, bool verbose = true) {
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

#include "glaze/json.hpp"

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

std::optional<Authorization> automated_authorization(std::string clientID, std::vector<std::string> scopes, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true) {
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
std::optional<Authorization> automated_authorization(std::string clientID, int scopeFlags = Scope::Profile, std::optional<std::string> clientSecret = {}, std::optional<uint16_t> port = {}, bool verbose = true) {
	return automated_authorization(clientID, scopes_to_strings(scopeFlags), clientSecret, port, verbose);
}


TEST_CASE("manual_automated_authorization" * doctest::skip()) {
	// TODO: Test public token authorization!
	SUBCASE("chat:write"){
		auto auth = automated_authorization(cstream::testing::credentials::clidentID, {"chat:write"}, cstream::testing::credentials::clientSecret);
		CHECK(auth.has_value() == true);
		CHECK(auth->code.empty() == false);
		CHECK(auth->refreshToken.empty() == true);
	}

	SUBCASE("offline_access"){
		auto auth = automated_authorization(cstream::testing::credentials::clidentID, Scope::ChatWrite | Scope::OfflineAccess, cstream::testing::credentials::clientSecret);
		CHECK(auth.has_value() == true);
		CHECK(auth->code.empty() == false);
		CHECK(auth->refreshToken.empty() == false);
	}
}