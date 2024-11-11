//
// made by Val (GH: theval-s) 2024
//
#include "crypto_lab2.h"

#include <iostream>
#include <iomanip>
#include <format>
#include <sstream>
#include <ranges>
#include <algorithm>
#include <limits>
#include <cstring> //memcpy usage
#if __cplusplus < 202002L //std::format is used
#error "Compile with C++20 support."
#endif
int main()
{
	while (true) {
		std::cout << "Blowfish encryption/decryption.\n"
			"Your encryption key (hex string without spaces):\n>";
		std::string key;
		std::cin >> key;
		try {
			Blowfish model(key);

			bool needs_change = false;
			while (!needs_change) {
				std::cout << "1. Encrypt\n"
					"2. Decrypt\n"
					"3. Change key\n"
					"4. Exit\n>";
				char opt;
				std::cin >> opt;

				std::string input;
				switch (opt) {
				case '1':
					std::cout << "Enter the message you want to encrypt\n>";
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //to clear the previous input if it had more than 1 symbol)
					std::getline(std::cin, input);
					std::cout << model.encrypt_string(input) << std::endl << std::endl;
					break;
				case '2':
					std::cout << "Enter the message you want to decrypt (hex string)\n>";
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //to clear the previous input if it had more than 1 symbol)
					std::getline(std::cin, input);
					input.erase(remove_if(input.begin(), input.end(), isspace), input.end());
					std::cout << model.decrypt_hexstring(input) << std::endl << std::endl;
					break;
				case '3':
					needs_change = true;
					break;
				case '4':
					return 0;
				default:
					std::cout << "Invalid option\n";
					break;
				}
				/*
				std::string message = "jealousy turning saints into the sea";
				std::string encrypted = model.encrypt_string(message);
				std::string decrypted = model.decrypt_hexstring(encrypted);
				if (message != decrypted) {
					std::cerr << "Error! Something went wrong, decrypted does not match original message";
				}
				else std::cout << encrypted << std::endl << model.decrypt_hexstring(encrypted);
				*/

#ifdef WIN32
				if (!needs_change) system("pause");
				system("cls");
#elif defined(__linux__) || defined(__unix__)
				if (!needs_change) system("read");
				system("clear");
#endif			

			}
		}
		catch (const std::exception& e) {
			std::cout << "Error! Exception: " << e.what() << std::endl;
		}
	}
	return 0;
	
}


uint32_t Blowfish::F(uint32_t x)
{
	unsigned char a = x>>24, 
		b = x>>16 & 0xFF, 
		c = x>>8 & 0xFF, 
		d = x & 0xFF;
	return ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
}

/// <summary>
/// encrypts 2 uint32_t using blowfish algorithm and s,p initialised by key
/// </summary>
/// <param name="il"></param>
/// <param name="ir"></param>
void Blowfish::encrypt(uint32_t& il, uint32_t& ir) {
	uint32_t cl = il, cr = ir;

	for (int i = 0; i < 16; i++) {
		cl ^= P[i];
		cr = F(cl) ^ cr;
		std::swap(cl, cr);
	}
	std::swap(cl, cr);
	cr ^= P[16];
	cl ^= P[17];
	il = cl;
	ir = cr;
}

/// <summary>
/// decrypts 2 uint32_t ecnrypted by blowfish algo using the s,p initialised by key
/// </summary>
/// <param name="il"></param>
/// <param name="ir"></param>
void Blowfish::decrypt(uint32_t& il, uint32_t& ir){
	uint32_t cl = il, cr = ir;

	for (int i = 17; i > 1; i--) {
		cl ^= P[i];
		cr = F(cl) ^ cr;
		std::swap(cl, cr);
	}
	std::swap(cl, cr);
	cr ^= P[1];
	cl ^= P[0];
	il = cl;
	ir = cr;
}

/// <summary>
/// 
/// </summary>
/// <param name="key">hex string of key without spaces, 32 to 448 bits in size (8-112 length in hex string)</param>
Blowfish::Blowfish(const std::string &key) {
	if (key.size() % 2 != 0) throw(std::invalid_argument("Key length must be even"));
	if (key.size() < 8 || key.size() > 112) throw(std::invalid_argument("invalid size of key"));
	int key_index = 0;

	for (int i = 0; i < 18; i++) {
		uint32_t data = 0; 
		for (int j = 0; j < 4; j++) {
			std::stringstream key_byte;
			key_byte << std::hex << key[key_index] << key[key_index+1];
			uint32_t hex_key = 0;
			if(!(key_byte >> hex_key)) throw std::invalid_argument("Invalid hex character in key while initializing");
			data = (data << 8) | hex_key;
			key_index = (key_index + 2) % key.size();
		}
		//XOR default values with the data from key
		P[i] = starter_P[i] ^ data;
	}
	
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 256; j++) S[i][j] = starter_S[i][j];
	}
	//key expansion
	uint32_t l = 0, r = 0;
	for (int i = 0; i < 18; i += 2) {
		Blowfish::encrypt(l, r);
		P[i] = l;
		P[i + 1] = r;
	}

	//filling s boxes
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 256; j += 2) {
			Blowfish::encrypt(l, r);
			S[i][j] = l;
			S[i][j + 1] = r;
		}
	}
}

/// <summary>
/// decrypts a string using blowfish algorithm. by default assumes little endian
/// </summary>
/// <param name="input"></param>
/// <returns></returns>
std::string Blowfish::encrypt_string(std::string &input){
	//adding padding, because algorithm works with 64bit blocks
	size_t len = input.length();
	size_t padding_len = (len % 8 == 0) ? 0 : 8 - (len + 8) % 8;
	input.append(padding_len, PADDING_VALUE);
	len = input.length();
	std::stringstream ss;
	for (size_t i = 0; i < len; i += 8) {
		uint32_t l = 0, r = 0;
		std::memcpy(&l, &input[i], 4);
		this->byte_reverse(l); //endianness
		std::memcpy(&r, &input[i + 4], 4);
		this->byte_reverse(r);
		this->encrypt(l, r);

		ss << std::format("{:08X}{:08X}", l, r);
	}
	return ss.str();
}

/// <summary>
/// Decrypts a hex string, encrypted by Blowfish algorithm
/// </summary>
/// <param name="input">-string to be decrypted. won't be modified. must be divisible by 16</param>
/// <returns>Decrypted string in default encoding</returns>
std::string Blowfish::decrypt_hexstring(const std::string &input){
	size_t len = input.length();
	if (len % 16 != 0) throw std::invalid_argument("decrypt_hexstring input string length must be divisible by 16");
	std::string inp_copy = input;
	//inp_copy.append((8 - (len + 8) % 8), PADDING_VALUE); 
	std::stringstream ss;
	for (size_t i = 0; i < len; i += 16) {
		uint32_t l = 0, r = 0;
		std::stringstream hex_stream;
		hex_stream << std::hex;
		for (int j = 0; j < 8; j++) hex_stream << inp_copy[i + j];
		if (!(hex_stream >> l)) throw std::invalid_argument("invalid hex number in decrypt_hexstring");
		hex_stream.str(std::string());
		hex_stream.clear();
		for (int j = 8; j < 16; j++) hex_stream << inp_copy[i + j];
		if (!(hex_stream >> r)) throw std::invalid_argument("invalid hex number in decrypt_hexstring");
		this->decrypt(l, r);

		//converting output from uints to chars
		char buffer[8];
		this->byte_reverse(l); //endianness
		this->byte_reverse(r); 
		memcpy(buffer, &l, 4);
		memcpy(buffer + 4, &r, 4);
		for (int j = 0; j < 8; j++) ss << buffer[j];
	}
	return ss.str();
}

void Blowfish::byte_reverse(uint32_t &num) {
	uint32_t t1 = num << 24, //last byte at 0x78000000
		t2 = num >> 24; //first byte at 0x00000012
	num &= 0x00FFFF00;
	num |= t1 | t2;
	t1 = (num >> 8) & 0x0000FF00; //0x00003400
	//0x00123456
	t2 = (num << 8) & 0x00FF0000; //0x00560000
	//0x34567800
	num &= 0xFF0000FF;
	num |= t1 | t2;
}
