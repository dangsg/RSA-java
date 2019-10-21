import java.math.BigInteger;
import java.lang.Math;
import java.util.Random;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import java.io.UnsupportedEncodingException;

public class RSA {
	private static final BigInteger ZERO = new BigInteger("0");
	private static final BigInteger ONE = new BigInteger("1");

	public static void main(String[] args) {
		try {
			RSA app = new RSA();
			String action = args[0];
			if (action.compareTo("genkey") == 0) {
				app.gen1024BitsKey();
			}
			else if (action.compareTo("encrypt") == 0) {
				app.encrypt();
			}
			else if (action.compareTo("decrypt") == 0) {
				app.decrypt();
			}
			else if (action.compareTo("crypt") == 0) {
				app.encrypt();
				app.decrypt();
			}
		} 
		catch (Exception e) {
			System.out.println(e);
		}	
	}

	private void gen1024BitsKey() {
		BigInteger p = BigInteger.probablePrime(512, new Random());
		BigInteger q = BigInteger.probablePrime(512, new Random());
		BigInteger n = p.multiply(q);
		BigInteger phi_n = p.subtract(new BigInteger("1")).multiply(q.subtract(new BigInteger("1")));
		BigInteger e, d;
		while (true) {
			e = (new BigInteger(512, new Random())).mod(phi_n);
			if (e.gcd(phi_n).equals(ONE)) {
				d = extendedEuclid(phi_n, e);
				if (d.compareTo(ZERO) >= 1 && d.compareTo(phi_n) <= 0) {
					break;
				}
			}

		}
		try {
			File publicKeyFile = new File("publicKey.txt");
			publicKeyFile.createNewFile();
			
			File privateKeyFile = new File("privateKey.txt");
			privateKeyFile.createNewFile();
			
			FileWriter publicKeyWriter = new FileWriter("publicKey.txt");
			publicKeyWriter.write(e.toString() + "\n");
			publicKeyWriter.write(n.toString() + "\n");
			publicKeyWriter.close();

			FileWriter privateKeyWriter = new FileWriter("privateKey.txt");
			privateKeyWriter.write(d.toString() + "\n");
			privateKeyWriter.write(n.toString() + "\n");
			privateKeyWriter.close();

			System.out.println("Generate keys successfully.");

		} catch (IOException err) {
			System.out.println("Key generating error occurred.");
			err.printStackTrace();
		}
	}

	private BigInteger extendedEuclid(BigInteger m, BigInteger b) {
		BigInteger[] firstArray = {new BigInteger("1"), new BigInteger("0"), m};
		BigInteger[] secondArray = {new BigInteger("0"), new BigInteger("1"), b};

		while (true) {
			if (secondArray[2].equals(ZERO)) {
				return new BigInteger("-1");
			}
			if (secondArray[2].equals(ONE)) {
				return secondArray[1];
			}
			BigInteger q = firstArray[2].divide(secondArray[2]);
			BigInteger[] tempArray = {
				firstArray[0].subtract(q.multiply(secondArray[0])), 
				firstArray[1].subtract(q.multiply(secondArray[1])), 
				firstArray[2].subtract(q.multiply(secondArray[2]))
			};
			firstArray = secondArray;
			secondArray = tempArray;
		} 
	}

	private String getText(String fileName) {
		try {
			File openedFile = new File(fileName);
			FileReader openedFileReader = new FileReader(openedFile);
			String text = "";
			int i;
			while ((i = openedFileReader.read()) != -1) {
				text += (char)i;
			}
			openedFileReader.close();
			return text;
		} catch (IOException e) {
			System.out.println("Reading text file error occurred.");
			e.printStackTrace();
			return null;
		}

	}

	private BigInteger[] getKey(String fileName) {
		try {
			File keyFile = new File(fileName);
			FileReader keyFileReader = new FileReader(keyFile);
			String firstKeyString = "";
			String secondKeyString = "";
			int i;
			while ((i = keyFileReader.read()) != '\n') {
				firstKeyString += (char)i;
			}
			while ((i = keyFileReader.read()) != '\n') {
				secondKeyString += (char)i;
			}
			keyFileReader.close();
			BigInteger[] key = {new BigInteger(firstKeyString), new BigInteger(secondKeyString)};
			return key;
		} catch (IOException e) {
			System.out.println("Reading key file error occurred.");
			e.printStackTrace();
			return null;
		}
	}	

	private void saveText(String fileName, String text) {
		try {
			File textFile = new File(fileName);
			textFile.createNewFile();
			FileWriter textFileWriter = new FileWriter(fileName);
			textFileWriter.write(text);
			textFileWriter.close();
		} catch (IOException e) {
			System.out.println("Reading text file error occurred.");
			e.printStackTrace();
		}
	}

	private void encrypt() {
		try {
			String plaintext = getText("plaintext.txt");
			BigInteger[] key = getKey("publicKey.txt");
			BigInteger e = key[0];
			BigInteger n = key[1];

			int encryptedBlockSize = (int)((n.toString(2).length() - 1) / 16) * 16;
			String hexPlaintext = String.format("%x", new BigInteger(1, plaintext.getBytes("Unicode"))).substring(4);
			int binPlaintextLength = hexPlaintext.length() * 4;
			BigInteger decPlaintext = new BigInteger(hexPlaintext, 16);
			String binPlaintextString = String.format("%" + binPlaintextLength + "s", decPlaintext.toString(2)).replace(" ", "0");
			String hexPlaintext2 = decPlaintext.toString(16);
			ArrayList<String> binPlaintextArray = new ArrayList<String>();
			int i = 0;
			// System.out.println(hexPlaintext);
			while (i < binPlaintextLength) {
				int j = i + encryptedBlockSize;
				if (j > binPlaintextLength) {
					j = binPlaintextLength;
				}
				binPlaintextArray.add(binPlaintextString.substring(i, j));
				// System.out.println(j - i);
				i = j;
			}

			ArrayList<String> binCiphertextArray = new ArrayList<String>();
			binPlaintextArray.forEach(str -> {
				BigInteger plainNum = new BigInteger(str, 2);
				// System.out.println(plainNum);
				BigInteger cipherNum = plainNum.modPow(e, n);
				binCiphertextArray.add(String.format("%1024s", cipherNum.toString(2)).replace(" ", "0"));
			});

			String binCiphertext = String.join("", binCiphertextArray);
			BigInteger decCiphertext = new BigInteger(binCiphertext, 2);
			// String hexCiphertext = "feff" + decCiphertext.toString(16);
			String hexCiphertext = decCiphertext.toString(16);
			// String ciphertext = new String(Hex.decodeHex(hexCiphertext.toCharArray()), "Unicode");

			// saveText("ciphertext.txt", ciphertext);
			saveText("ciphertext.txt", hexCiphertext);
			System.out.println("Encrypt successfully!");

			// System.out.println(encryptedBlockSize);//testing
			// System.out.println(plaintext.length());//testing

		}
		catch (UnsupportedEncodingException err) {
			System.out.println("Encoding type is not supported!");
			err.printStackTrace();
		}
		// catch (DecoderException err) {
		// 	System.out.println("Hex decoding error occurred!");
		// 	err.printStackTrace();
		// }
	}	

	private void decrypt() {
		try {
			// String hexCiphertext = getText("ciphertext.txt").substring(4);
			String hexCiphertext = getText("ciphertext.txt");
			BigInteger[] key = getKey("privateKey.txt");
			BigInteger d = key[0];
			BigInteger n = key[1];

			int decryptedBlockSize = 1024;
			// String hexCiphertext = String.format("%x", new BigInteger(1, ciphertext.getBytes("Unicode"))).substring(4);
			BigInteger decCiphertext = new BigInteger(hexCiphertext, 16);
			int binCiphertextLength = hexCiphertext.toString().length() * 4;
			String binCiphertextString = String.format("%" + binCiphertextLength + "s", decCiphertext.toString(2)).replace(" ", "0");
			ArrayList<String> binCiphertextArray = new ArrayList<String>();
			int i = 0;
			while (i < binCiphertextLength) {
				int j = i + decryptedBlockSize;
				if (j > binCiphertextLength) {
					j = binCiphertextLength;
				}
				binCiphertextArray.add(binCiphertextString.substring(i, j));
				i = j;
			}

			ArrayList<String> binDeciphertextArray = new ArrayList<String>();
			binCiphertextArray.forEach(str -> {
				BigInteger cipherNum = new BigInteger(str, 2);
				BigInteger decipherNum = cipherNum.modPow(d, n);
				String binDecipherNum = decipherNum.toString(2);
				while (binDecipherNum.length() % 16 != 0) {
					binDecipherNum = "0" + binDecipherNum;
				}
				binDeciphertextArray.add(binDecipherNum);
				// System.out.println(binDecipherNum.length());
			});

			String binDeciphertext = String.join("", binDeciphertextArray);
			BigInteger decDeciphertext = new BigInteger(binDeciphertext, 2);
			String hexDeciphertext = decDeciphertext.toString(16);
			while (hexDeciphertext.length() % 4 != 0) {
				hexDeciphertext = "0" + hexDeciphertext;
			}
			// System.out.println(hexDeciphertext);//testing
			hexDeciphertext = "feff" + hexDeciphertext;
			String deciphertext = new String(Hex.decodeHex(hexDeciphertext.toCharArray()), "Unicode");

			saveText("deciphertext.txt", deciphertext);
			System.out.println("Decrypt successfully!");


		}
		catch (UnsupportedEncodingException err) {
			System.out.println("Encoding type is not supported!");
			err.printStackTrace();
		}
		catch (DecoderException err) {
			System.out.println("Hex decoding error occurred!");
			err.printStackTrace();
		}
	}

}