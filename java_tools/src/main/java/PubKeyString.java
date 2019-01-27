import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class PubKeyString {

    private static final int KEY_LENGTH = 4096;
    private static final String CSR_COMMON_NAME = "readme.q0f.pw";

    // function to calculate LCM of two large numbers
    private static BigInteger lcm(BigInteger s, BigInteger s1) {
        // calculate multiplication of two bigintegers
        BigInteger mul = s.multiply(s1);

        // calculate gcd of two bigintegers
        BigInteger gcd = s.gcd(s1);

        // calculate lcm using formula: lcm * gcd = x * y
        BigInteger lcm = mul.divide(gcd);
        return lcm;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, OperatorCreationException {
        // Hex version of a string that's interesting when base64 encoded.
        String message;
        if (args.length > 0) {
            message = args[0];
        } else {
            message = "Hello World";
        }

        if (message.length() > KEY_LENGTH/6 - 3) {
            System.out.println("Message is greater than maximum allowed length.");
        }
        while (message.length() < KEY_LENGTH/6 - 3) {
            message = "+" + message + "+";
        }

        while ((message.length() % 4) != 0) {
            message += "A";
        }

        String goal = toHex(Base64.getDecoder().decode(message.replace(" ", "+")));
        // Because the length of the bytes preceding the public key in the final cert will probably not be
        // an even multiple of 3, we need to pad the leading bytes. Trial and error suggests we need to add
        // 1 byte, but try values of 0 or 2 if it doesn't seem to work.
        for (int i = 0; i < 1; i++) {
            goal = "ff" + goal;
        }

        // Pad out the goal to make a full 4096 bit key modulus.
        while (goal.length() < KEY_LENGTH/4) {
            goal = goal + "00";
        }

        // LE doesn't allow primes less than 752 in the key. So we choose the next smallest one. ;)
        // https://github.com/letsencrypt/boulder/blob/master/goodkey/good_key.go#L17
        BigInteger q = BigInteger.valueOf(757);
        BigInteger goalInt = new BigInteger(goal, 16);
        if (!goalInt.mod(q).equals(BigInteger.ZERO)) {
            goalInt = goalInt.add(q.subtract(goalInt.mod(q)));
        }
        assert(goalInt.mod(q).equals(BigInteger.ZERO));

        BigInteger p = goalInt.divide(q);
        while (!p.isProbablePrime(10000)) {
            p = p.add(BigInteger.ONE);
        }
        System.out.println("p=" + p);
        System.out.println("q=" + q);

        BigInteger n = p.multiply(q);
        System.out.println("n = " + Base64.getEncoder().encodeToString(n.toByteArray()));

        BigInteger lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("10001", 16);
        BigInteger d = e.modInverse(lambda);

        RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(n, d));
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

        System.out.println("privateKey: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("publicKey: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        PKCS10CertificationRequest csr = new PKCS10CertificationRequestBuilder(new X500Name("CN=" + CSR_COMMON_NAME), bcPk)
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));
        System.out.println("csr: " + Base64.getEncoder().encodeToString(csr.getEncoded()));
    }
}

