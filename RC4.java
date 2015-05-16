package Transmitter;
/*RC4 algorithm is a symmetric encryption algorithm as the same key is used for 
 * both encryption and decryption.An input key is fed to a pseudorandom generator 
 * which produces a random output keystream. This keystream is xored with the input plaintext
 * to produce ciphertext. The same keystream is used for decryption.*/
 
import java.util.*;
import java.net.*;
import java.io.*;

public class RC4 {
	private byte[] S;
	private int[] T;
	private int keylen;
	private byte[] key;
	private static byte[] key_8bytes = new byte[] {56, 34, 100, 92, 36, 45, 38, 57};
	
	public RC4(byte[] nonce) throws Exception {
		byte[] input_key = new byte[16];
		input_key[0] = key_8bytes[0];
		input_key[1] = nonce[0];
		input_key[2] = key_8bytes[1];
		input_key[3] = nonce[1];
		input_key[4] = key_8bytes[2];
		input_key[5] = nonce[2];
		input_key[6] = key_8bytes[3];
		input_key[7] = nonce[3];
		input_key[8] = key_8bytes[4];
		input_key[9] = nonce[4];
		input_key[10] = key_8bytes[5];
		input_key[11] = nonce[5];
		input_key[12] = key_8bytes[6];
		input_key[13] = nonce[6];
		input_key[14] = key_8bytes[7];
		input_key[15] = nonce[7];
		S = new byte[256];
		T = new int[256];
		keylen = key_8bytes.length; 
		key=key_8bytes;
	}
	
	// Function to encrypt the plaintext received using RC4 algorithm
	public byte[] encrypt(byte[] plaintext) throws Exception {
		byte[] ciphertext = new byte[plaintext.length];
		if (keylen < 1 || keylen > 256) {
			throw new Exception("key must be between 1 and 256 bytes");
		}
		else {
			// Initialization
			for (int i = 0; i < 256; i++) {
				S[i] = (byte) i;
				T[i] = key[i % keylen];
			}

			// Initialization Permutations
			int j = 0;
			byte temp;
			for (int i = 0; i < 256; i++) {
				j = (j + S[i] + 128 + T[i] + 128) % 256;
				temp = S[i];
				S[i]=S[j];
				S[j]=temp;
			}

			// Stream Generation
			int t = 0;
			byte k;
			int i = 0, c = 0;
			j = 0;
			while(c<ciphertext.length) {
				i = ((i + 1) % 256);
				j = ((j + S[i] + 128) % 256);
				temp = S[i];
				S[i]=S[j]; // Swap
				S[j]=temp;
				t = ((S[i] + S[j] + 128 + 128) % 256);
				k = S[t]; // Keystream is generated
				ciphertext[c] = (byte) (k ^ plaintext[c]);
				c++;
			}
		}
		return ciphertext;
	}
	
	// Function to decrypt the ciphertext using RC4 algorithm. This function simply calls encrypt()
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		return encrypt(ciphertext);
	}
}





