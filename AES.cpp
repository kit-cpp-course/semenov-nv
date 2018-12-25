#include "pch.h"
#include "AES.h"

//Беззнаковый <<
unsigned char rj_xtime(unsigned char x);

// заполняем оригинальный ключевой вектор
AES::AES(const ByteArray & key)
	: m_key(ByteArray(key.size() > KEY_SIZE ? KEY_SIZE : key.size(), 0)),
	m_salt(ByteArray(KEY_SIZE - m_key.size(), 0)), m_rkey(ByteArray(KEY_SIZE, 0)), m_buffer_pos(0),
	m_remainingLength(0), m_decryptInitialized(false) 
{
	for (ByteArray::size_type i = 0; i < m_key.size(); ++i)
	{
		m_key[i] = key[i];
	}
}



// создаем полный ключ (если оригинал <256 бит)
ByteArray::size_type AES::encrypt_start(const ByteArray::size_type plain_length, ByteArray &encrypted) {
	m_remainingLength = plain_length;

	// генерируем соль
	// Соль, это добивка ключа до нужного размера
	for (unsigned char &i : m_salt) {
		i = (rand() & 0xFF);
	}

	// 
	// Рассчитаnm заполнение
	ByteArray::size_type padding = 0;
	if (m_remainingLength % BLOCK_SIZE != 0)
	{
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
ByteArray::size_type
AES::encrypt_continue(const unsigned char *plain, const ByteArray::size_type plain_length, ByteArray &encrypted) {
	ByteArray::size_type i = 0;

	while (i < plain_length) {
		m_buffer[m_buffer_pos++] = plain[i++];

		checkEnc(encrypted);
	}

	return encrypted.size();
}

//Если блок соответствует размеру
void AES::checkEnc(ByteArray &encrypted) {
	if (m_buffer_pos == BLOCK_SIZE) {
		encrypt(m_buffer);

		for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; m_buffer_pos++) {
			encrypted.push_back(m_buffer[m_buffer_pos]);
			m_remainingLength--;
		}

		m_buffer_pos = 0;
	}
}


// завершаем процесс шифрования
ByteArray::size_type AES::encrypt_end(ByteArray &encrypted) {
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


// реализация базового алгоритма
void AES::encrypt(unsigned char *buffer) {
	unsigned char i, rcon;

	copy_key();
	add_round_key(buffer, 0);
	for (i = 1, rcon = 1; i < NUM_ROUNDS; ++i) {
		sub_bytes(buffer);
		shift_rows(buffer);
		mix_columns(buffer);
		if (!(i & 1)) expand_enc_key(&rcon);
		add_round_key(buffer, i);
	}
	sub_bytes(buffer);
	shift_rows(buffer);
	expand_enc_key(&rcon);
	add_round_key(buffer, i);
}

ByteArray::size_type AES::decrypt_start(const ByteArray::size_type encrypted_length) {
	m_remainingLength = encrypted_length;

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

ByteArray::size_type
AES::decrypt_continue(const unsigned char *encrypted, const ByteArray::size_type encrypted_length,
	ByteArray &plain) {
	ByteArray::size_type i = 0;

	while (i < encrypted_length) {
		m_buffer[m_buffer_pos++] = encrypted[i++];

		checkDec(plain);
	}

	return plain.size();
}

void AES::checkDec(ByteArray &plain) {
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
	else if (m_decryptInitialized && m_buffer_pos == BLOCK_SIZE) 
	{
		decrypt(m_buffer);

		for (m_buffer_pos = 0; m_buffer_pos < BLOCK_SIZE; ++m_buffer_pos) 
		{
			if (m_remainingLength > 0) {
				plain.push_back(m_buffer[m_buffer_pos]);
				--m_remainingLength;
			}
		}

		m_buffer_pos = 0;
	}
}

ByteArray::size_type AES::decrypt_end(ByteArray &plain) {
	return plain.size();
}

void AES::decrypt(unsigned char *buffer) {
	unsigned char i, rcon = 1;

	copy_key();
	for (i = NUM_ROUNDS / 2; i > 0; --i) {
		expand_enc_key(&rcon);
	}

	add_round_key(buffer, NUM_ROUNDS);
	shift_rows_inv(buffer);
	sub_bytes_inv(buffer);

	for (i = NUM_ROUNDS, rcon = 0x80; --i;)
	{
		if ((i & 1)) {
			expand_dec_key(&rcon);
		}
		add_round_key(buffer, i);
		mix_columns_inv(buffer);
		shift_rows_inv(buffer);
		sub_bytes_inv(buffer);
	}
	add_round_key(buffer, i);
}

void AES::expand_enc_key(unsigned char *rc) {
	unsigned char i;

	m_rkey[0] = m_rkey[0] ^ sbox[m_rkey[29]] ^ (*rc);
	m_rkey[1] = m_rkey[1] ^ sbox[m_rkey[30]];
	m_rkey[2] = m_rkey[2] ^ sbox[m_rkey[31]];
	m_rkey[3] = m_rkey[3] ^ sbox[m_rkey[28]];
	*rc = FE(*rc);

	for (i = 4; i < 16; i += 4) {
		m_rkey[i] = m_rkey[i] ^ m_rkey[i - 4];
		m_rkey[i + 1] = m_rkey[i + 1] ^ m_rkey[i - 3];
		m_rkey[i + 2] = m_rkey[i + 2] ^ m_rkey[i - 2];
		m_rkey[i + 3] = m_rkey[i + 3] ^ m_rkey[i - 1];
	}
	m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
	m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
	m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
	m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

	for (i = 20; i < 32; i += 4) {
		m_rkey[i] = m_rkey[i] ^ m_rkey[i - 4];
		m_rkey[i + 1] = m_rkey[i + 1] ^ m_rkey[i - 3];
		m_rkey[i + 2] = m_rkey[i + 2] ^ m_rkey[i - 2];
		m_rkey[i + 3] = m_rkey[i + 3] ^ m_rkey[i - 1];
	}
}

void AES::expand_dec_key(unsigned char *rc) {
	unsigned char i;

	for (i = 28; i > 16; i -= 4) {
		m_rkey[i + 0] = m_rkey[i + 0] ^ m_rkey[i - 4];
		m_rkey[i + 1] = m_rkey[i + 1] ^ m_rkey[i - 3];
		m_rkey[i + 2] = m_rkey[i + 2] ^ m_rkey[i - 2];
		m_rkey[i + 3] = m_rkey[i + 3] ^ m_rkey[i - 1];
	}

	m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
	m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
	m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
	m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

	for (i = 12; i > 0; i -= 4) {
		m_rkey[i + 0] = m_rkey[i + 0] ^ m_rkey[i - 4];
		m_rkey[i + 1] = m_rkey[i + 1] ^ m_rkey[i - 3];
		m_rkey[i + 2] = m_rkey[i + 2] ^ m_rkey[i - 2];
		m_rkey[i + 3] = m_rkey[i + 3] ^ m_rkey[i - 1];
	}

	*rc = FD(*rc);
	m_rkey[0] = m_rkey[0] ^ sbox[m_rkey[29]] ^ (*rc);
	m_rkey[1] = m_rkey[1] ^ sbox[m_rkey[30]];
	m_rkey[2] = m_rkey[2] ^ sbox[m_rkey[31]];
	m_rkey[3] = m_rkey[3] ^ sbox[m_rkey[28]];
}

void AES::sub_bytes(unsigned char *buffer) {
	unsigned char i = KEY_SIZE / 2;

	while (i--) buffer[i] = sbox[buffer[i]];
}

void AES::sub_bytes_inv(unsigned char *buffer) {
	unsigned char i = KEY_SIZE / 2;

	while (i--) buffer[i] = sboxinv[buffer[i]];
}

void AES::copy_key() {
	ByteArray::size_type i;

	for (i = 0; i < m_key.size(); ++i) {
		m_rkey[i] = m_key[i];
	}
	for (i = 0; i < m_salt.size(); ++i) {
		m_rkey[i + m_key.size()] = m_salt[i];
	}
}

void AES::add_round_key(unsigned char *buffer, const unsigned char round) {
	unsigned char i = KEY_SIZE / 2;

	while (i--) buffer[i]  = m_rkey[(round & 1) ? i + 16 : i];
}

void AES::shift_rows(unsigned char *buffer) {
	unsigned char i, j, k, l; // чтобы сделать его потенциально параллельным :) 

	i = buffer[1];
	buffer[1] = buffer[5];
	buffer[5] = buffer[9];
	buffer[9] = buffer[13];
	buffer[13] = i;

	j = buffer[10];
	buffer[10] = buffer[2];
	buffer[2] = j;

	k = buffer[3];
	buffer[3] = buffer[15];
	buffer[15] = buffer[11];
	buffer[11] = buffer[7];
	buffer[7] = k;

	l = buffer[14];
	buffer[14] = buffer[6];
	buffer[6] = l;
}

void AES::shift_rows_inv(unsigned char *buffer) {
	unsigned char i, j, k, l; // то же, что и выше :) 

	i = buffer[1];
	buffer[1] = buffer[13];
	buffer[13] = buffer[9];
	buffer[9] = buffer[5];
	buffer[5] = i;

	j = buffer[2];
	buffer[2] = buffer[10];
	buffer[10] = j;

	k = buffer[3];
	buffer[3] = buffer[7];
	buffer[7] = buffer[11];
	buffer[11] = buffer[15];
	buffer[15] = k;

	l = buffer[6];
	buffer[6] = buffer[14];
	buffer[14] = l;
}

void AES::mix_columns(unsigned char *buffer) {
	unsigned char i, a, b, c, d, e;

	for (i = 0; i < 16; i += 4) {
		a = buffer[i];
		b = buffer[i + 1];
		c = buffer[i + 2];
		d = buffer[i + 3];

		e = a ^ b ^ c ^ d;

		buffer[i] ^= e ^ rj_xtime(a ^ b);
		buffer[i + 1] ^= e ^ rj_xtime(b ^ c);
		buffer[i + 2] ^= e ^ rj_xtime(c ^ d);
		buffer[i + 3] ^= e ^ rj_xtime(d ^ a);
	}
}

void AES::mix_columns_inv(unsigned char *buffer) {
	unsigned char i, a, b, c, d, e, x, y, z;

	for (i = 0; i < 16; i += 4) {
		a = buffer[i];
		b = buffer[i + 1];
		c = buffer[i + 2];
		d = buffer[i + 3];

		e = a ^ b ^ c ^ d;
		z = rj_xtime(e);
		x = e ^ rj_xtime(rj_xtime(z ^ a ^ c));
		y = e ^ rj_xtime(rj_xtime(z ^ b ^ d));

		buffer[i] ^= x ^ rj_xtime(a ^ b);
		buffer[i + 1] ^= y ^ rj_xtime(b ^ c);
		buffer[i + 2] ^= x ^ rj_xtime(c ^ d);
		buffer[i + 3] ^= y ^ rj_xtime(d ^ a);
	}
}

unsigned char rj_xtime(unsigned char x) {
	return static_cast<unsigned char>((x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1));
}
