#include "encrypt.h"
#include "AES.h"
const long BUFFER_SIZE = 1024;

Encrypt::Encrypt(FILE *inp, FILE *out, std::string pass) : AES(pass) {
	this->input = inp;
	this->output = out;
	this->pass = pass;
}

int Encrypt::work() {
	ByteArray key, enc;
	for (auto c : pass)
		key.push_back(c);

	if (input == 0) return 1;
	if (output == 0) return 2;


	fseek(input, 0, SEEK_END);
	size_t file_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	std::cout << "File size " << file_len << " bytes" << std::endl;
	start(file_len, key);

	enc.clear();
	start(file_len, enc);
	fwrite(enc.data(), enc.size(), 1, output);

	while (!feof(input)) {
		unsigned char buffer[BUFFER_SIZE];
		size_t buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
		std::cout << "Read " << buffer_len << " bytes" << std::endl;
		if (buffer_len > 0) {
			enc.clear();
			w_continue(buffer, buffer_len, enc);
			fwrite(enc.data(), enc.size(), 1, output);
		}
	}

	enc.clear();
	end(enc);
	fwrite(enc.data(), enc.size(), 1, output);

	fclose(input);
	fclose(output);

	return 0;
}

// создаем полный ключ (если оригинал <256 бит)
ByteArray::size_type Encrypt::start(const ByteArray::size_type plain_length, ByteArray & encrypted)
{
	m_remainingLength = plain_length;

	// генерируем соль
	// Соль, это добивка ключа до нужного размера
	for (unsigned char &i : m_salt) {
		i = (rand() & 0xFF);
	}

	// 
	// Рассчитаnm заполнение
	ByteArray::size_type padding = 0;
	if (m_remainingLength % BLOCK_SIZE != 0) {
		padding = (BLOCK_SIZE - (m_remainingLength % BLOCK_SIZE));
	}
	m_remainingLength += padding;

	// добовляем соль
	encrypted.insert(encrypted.end(), m_salt.begin(), m_salt.end());
	m_remainingLength += m_salt.size();

	//Добавляем 1 байт для размера заполнения
	encrypted.push_back(padding & 0xFF);
	++m_remainingLength;

	// сбрасываем буфер
	m_buffer_pos = 0;

	return encrypted.size();
}

// процесс шифрования
ByteArray::size_type Encrypt::w_continue(const unsigned char * plain, ByteArray::size_type plain_length, ByteArray & encrypted)
{
	ByteArray::size_type i = 0;

	while (i < plain_length) {
		m_buffer[m_buffer_pos++] = plain[i++];

		check(encrypted);
	}

	return encrypted.size();
}

// завершаем процесс шифрования
ByteArray::size_type Encrypt::end(ByteArray & encrypted)
{
	if (m_buffer_pos > 0) {
		while (m_buffer_pos < BLOCK_SIZE) {
			m_buffer[m_buffer_pos++] = 0;
		}

		encrypt(m_buffer);

		for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; m_buffer_pos++) {
			encrypted.push_back(m_buffer[m_buffer_pos]);
			m_remainingLength--;
		}

		m_buffer_pos = 0;
	}

	return encrypted.size();
}

void Encrypt::check(ByteArray & encrypted)
{
	if (m_buffer_pos == BLOCK_SIZE) {
		encrypt(m_buffer);

		for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; m_buffer_pos++) {
			encrypted.push_back(m_buffer[m_buffer_pos]);
			m_remainingLength--;
		}

		m_buffer_pos = 0;
	}
}