#include <vector>
#include <string>
#include <numeric>

namespace cstream {

	enum Scope {
		ChatWrite = 1 << 1,             // chat:write
		BillingPrivateRead = 1 << 2,    // billing:private:read
		OfflineAccess = 1 << 3,         // offline_access
		OpenID = 1 << 4,                // openid
		Profile = 1 << 5,               // profile
		VideoPrivateRead = 1 << 6,      // video:private:read
	};

	inline std::vector<std::string> scopes_to_strings(int scopeFlags) {
		std::vector<std::string> out;
		if(scopeFlags & ChatWrite) out.emplace_back("chat:write");
		if(scopeFlags & BillingPrivateRead) out.emplace_back("billing:private:read");
		if(scopeFlags & OfflineAccess) out.emplace_back("offline_access");
		if(scopeFlags & OpenID) out.emplace_back("openid");
		if(scopeFlags & Profile) out.emplace_back("profile");
		if(scopeFlags & VideoPrivateRead) out.emplace_back("video:private:read");
		return out;
	}

	inline std::string scopes_from_list(std::vector<std::string> scopes) {
		if(scopes.empty()) return "";
		return std::accumulate(std::next(scopes.begin()), scopes.end(), scopes[0],
			[](std::string a, std::string b) {
				return a + " " + b;
			}
		);
	}
	inline std::string scopes_from_list(int scopeFlags) {
		return scopes_from_list(scopes_to_strings(scopeFlags));
	}

}



#ifdef CSTREAM_BUILD_TESTS
#include "doctest/doctest.h"

TEST_CASE("scopes_to_strings") {
	using namespace cstream;
	CHECK(scopes_to_strings(Scope::ChatWrite) == std::vector<std::string>{"chat:write"});
	CHECK(scopes_to_strings(Scope::BillingPrivateRead) == std::vector<std::string>{"billing:private:read"});
	CHECK(scopes_to_strings(Scope::OfflineAccess) == std::vector<std::string>{"offline_access"});
	CHECK(scopes_to_strings(Scope::OpenID) == std::vector<std::string>{"openid"});
	CHECK(scopes_to_strings(Scope::Profile) == std::vector<std::string>{"profile"});
	CHECK(scopes_to_strings(Scope::VideoPrivateRead) == std::vector<std::string>{"video:private:read"});

	CHECK(scopes_to_strings(Scope::ChatWrite | Scope::VideoPrivateRead) == std::vector<std::string>{"chat:write", "video:private:read"});
}
#endif // CSTREAM_BUILD_TESTS