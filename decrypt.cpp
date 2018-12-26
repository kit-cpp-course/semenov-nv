#include "decrypt.h"
#include "AES.h"
#include <iostream>
#include <ctime>
const long BUFFER_SIZE = 1024;

Decrypt::Decrypt(FILE *inp, FILE *out, std::string pass) : AES(pass) {
	this->input = inp;
	this->output = out;
	this->pass = pass;
}

inline int Decrypt::work() {
	ByteArray key, dec;
	size_t file_len;

	srand(time(0));
	for (auto c : pass) {
		key.push_back(c);
	}
	if (input == 0) return 1;
	if (output == 0) return 2;
	fseek(input, 0, SEEK_END);
	file_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	std::cout << "File size " << file_len << " bytes" << std::endl;
	start(file_len,key);//key

	while (!feof(input)) {
		unsigned char buffer[BUFFER_SIZE];
		size_t buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
		std::cout << "Read " << buffer_len << " bytes" << std::endl;
		if (buffer_len > 0) {
			dec.clear();
			w_continue(buffer, buffer_len, dec);
			fwrite(dec.data(), dec.size(), 1, output);
		}
	}

	dec.clear();
	end(dec);
	fwrite(dec.data(), dec.size(), 1, output);

	fclose(input);
	fclose(output);

	return 0;
}

ByteArray::size_type Decrypt::start(ByteArray::size_type plain_length, ByteArray &encrypted)
{
	m_remainingLength = plain_length;

	// Сбросить соль
	for (unsigned char j = 0; j < m_salt.size(); ++j) {
		m_salt[j] = 0;
	}
	m_remainingLength -= m_salt.size();


	// Сбросить буфер
	m_buffer_pos = 0;

	m_decryptInitialized = false;

	return m_remainingLength;
}

ByteArray::size_type Decrypt::w_continue(const unsigned char * plain, ByteArray::size_type plain_length, ByteArray & encrypted)
{
	ByteArray::size_type i = 0;

	while (i < plain_length) {
		m_buffer[m_buffer_pos++] = plain[i++];

		check(encrypted);
	}

	return encrypted.size();
}

ByteArray::size_type Decrypt::end(ByteArray & encrypted)
{
	return encrypted.size();
}

void Decrypt::check(ByteArray & encrypted)
{
	if (!m_decryptInitialized && m_buffer_pos == m_salt.size() + 1) {
		unsigned char j;
		ByteArray::size_type padding;

		// Получить соль
		for (j = 0; j < m_salt.size(); ++j) {
			m_salt[j] = m_buffer[j];
		}

		// Получить отступы
		padding = (m_buffer[j] & 0xFF);
		m_remainingLength -= padding + 1;

		// Начать расшифровку
		m_buffer_pos = 0;

		m_decryptInitialized = true;
	}
	else if (m_decryptInitialized && m_buffer_pos == BLOCK_SIZE) {
		decrypt(m_buffer);

		for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; m_buffer_pos++) {
			if (m_remainingLength > 0) {
				encrypted.push_back(m_buffer[m_buffer_pos]);
				m_remainingLength--;
			}
		}

		m_buffer_pos = 0;
	}
}

