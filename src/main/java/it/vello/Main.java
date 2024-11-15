package it.vello;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        RSAEncryptor rsa = new RSAEncryptor();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter plaintext to encrypt: ");
        String plaintext = scanner.nextLine();

        String ciphertext = rsa.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);

        String decrypted = rsa.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decrypted);
    }
}
