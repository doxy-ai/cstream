#pragma once

#include <string>
#include <vector>
#include <algorithm>

// From: https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329
/*
Base64 translates 24 bits into 4 ASCII characters at a time. First,
3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
translated into ASCII characters. That is, each 6-bit number is treated
as an index into the ASCII character array.
If the final set of bits is less 8 or 16 instead of 24, traditional base64
would add a padding character. However, if the length of the data is
known, then padding can be eliminated.
One difference between the "standard" Base64 is two characters are different.
See RFC 4648 for details.
This is how we end up with the Base64 URL encoding.
*/

const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

template<typename T>
std::string base64_encode(const T& in) {
	std::string out;
	out.reserve(127);
	int val = 0;
	int valb = -6;
	std::ranges::for_each(in, [&](unsigned char c) {
		val = (val<<8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
			valb -= 6;
		}
	});
	if (valb > -6) 
		out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
	return out;
}

template<typename Buffer>
std::string base64_decode(const Buffer& in) {
	std::string out;
	out.reserve(127);
	std::vector<int> T(256, -1);
	for (unsigned int i = 0; i < 64; i++) 
		T[base64_url_alphabet[i]] = i;
	int val = 0; 
	int valb = -8;
	std::ranges::for_each(in, [&](unsigned char c) {
		if (T[c] == -1) return;
		val = (val<<6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val>>valb)&0xFF));
			valb -= 8;
		}
	});
	return out;
}