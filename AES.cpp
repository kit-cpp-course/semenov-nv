#include "pch.h"
#include "AES.h"

//Беззнаковый <<
unsigned char rj_xtime(unsigned char x);

// заполняем оригинальный ключевой вектор
AES::AES(const std::string & key)
	: m_key(ByteArray(key.size() > KEY_SIZE ? KEY_SIZE : key.size())),
	m_salt(ByteArray(KEY_SIZE - m_key.size())), m_rkey(ByteArray(KEY_SIZE)), m_buffer_pos(0),
	m_remainingLength(0), m_decryptInitialized(false)
{
	for (ByteArray::size_type i = 0; i < m_key.size(); ++i) {
		m_key[i] = key[i];
	}
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

void AES::decrypt(unsigned char *buffer) {
	unsigned char i, rcon = 1;

	copy_key();
	for (i = NUM_ROUNDS / 2; i > 0; --i) {
		expand_enc_key(&rcon);
	}

	add_round_key(buffer, NUM_ROUNDS);
	shift_rows_inv(buffer);
	sub_bytes_inv(buffer);

	for (i = NUM_ROUNDS, rcon = 0x80; --i;) {
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
		expand(i);
	}
	m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
	m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
	m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
	m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

	for (i = 20; i < 32; i += 4) {
		expand(i);
	}
}

void AES::expand_dec_key(unsigned char *rc) {
	unsigned char i;

	for (i = 28; i > 16; i -= 4) {
		expand(i);
	}

	m_rkey[16] = m_rkey[16] ^ sbox[m_rkey[12]];
	m_rkey[17] = m_rkey[17] ^ sbox[m_rkey[13]];
	m_rkey[18] = m_rkey[18] ^ sbox[m_rkey[14]];
	m_rkey[19] = m_rkey[19] ^ sbox[m_rkey[15]];

	for (i = 12; i > 0; i -= 4) {
		expand(i);
	}

	*rc = FD(*rc);
	m_rkey[0] = m_rkey[0] ^ sbox[m_rkey[29]] ^ (*rc);
	m_rkey[1] = m_rkey[1] ^ sbox[m_rkey[30]];
	m_rkey[2] = m_rkey[2] ^ sbox[m_rkey[31]];
	m_rkey[3] = m_rkey[3] ^ sbox[m_rkey[28]];
}

void AES::expand(unsigned char i) {
	m_rkey[i + 0] = m_rkey[i + 0] ^ m_rkey[i - 4];
	m_rkey[i + 1] = m_rkey[i + 1] ^ m_rkey[i - 3];
	m_rkey[i + 2] = m_rkey[i + 2] ^ m_rkey[i - 2];
	m_rkey[i + 3] = m_rkey[i + 3] ^ m_rkey[i - 1];
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

	while (i--) {
		buffer[i] ^= m_rkey[(round & 1) ? i + 16 : i];
	}
}

void AES::shift_rows(unsigned char *buffer) {
	shift(buffer, new int[4]{ 1,5,9,13 }, new int[2]{ 10,2 }, new int[4]{ 3,15,11,7 }, new int[2]{ 14,6 });
}

void AES::shift_rows_inv(unsigned char *buffer) {
	shift(buffer, new int[4]{ 1,13,9,5 }, new int[2]{ 2,10 }, new int[4]{ 3,7,11,15 }, new int[2]{ 6,14 });
}

void AES::shift(unsigned char *buffer, int* a, int* b, int* c, int* d) {
	unsigned char i, j, k, l; // чтобы сделать его потенциально параллельным :)

	i = buffer[*a];
	buffer[*a] = buffer[*(a+1)];
	buffer[*(a+1)] = buffer[*(a+2)];
	buffer[*(a+2)] = buffer[*(a+3)];
	buffer[*(a+3)] = i;

	j = buffer[*b];
	buffer[*b] = buffer[*(b+1)];
	buffer[*(b+1)] = j;

	k = buffer[*c];
	buffer[*c] = buffer[*(c+1)];
	buffer[*(c+1)] = buffer[*(c+2)];
	buffer[*(c+2)] = buffer[*(c+3)];
	buffer[*(c+3)] = k;

	l = buffer[*d];
	buffer[*d] = buffer[*(d+1)];
	buffer[*(d+1)] = l;

	delete[] a;
	delete[] b;
	delete[] c;
	delete[] d;
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