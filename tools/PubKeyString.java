import netflix.shade.org.bouncycastle.v156.asn1.x500.X500Name;
import netflix.shade.org.bouncycastle.v156.asn1.x509.SubjectPublicKeyInfo;
import netflix.shade.org.bouncycastle.v156.operator.OperatorCreationException;
import netflix.shade.org.bouncycastle.v156.operator.jcajce.JcaContentSignerBuilder;
import netflix.shade.org.bouncycastle.v156.pkcs.PKCS10CertificationRequest;
import netflix.shade.org.bouncycastle.v156.pkcs.PKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class PubKeyString {

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

    private static BigInteger rand(int bitLen) {
        byte[] buffer = new byte[bitLen/8];
        new SecureRandom().nextBytes(buffer);
        buffer[0] &= 0x7f;
        return new BigInteger(buffer);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, OperatorCreationException {
        // Hex version of a string that's interesting when base64 encoded.
        String goal = "ffffffffffffc09fe000092f9e9dcaf2a6d8a89fe91ecbed3df85f7e" +
                "d75fb4dbef43fbbe3e137fb907e0fcfb8d7ee7af82e7eeb7fb9ebef3cf82" +
                "d3eb616adf9c6a67beb68fa9ae89a29de9dc7be8a7f8c6b2fb6d34efe8ac" +
                "f9a9fe7b16a6a657bea1ff9afa7ba66deafe7256a299e77eb68f9b7be6be" +
                "b1e72b7adf9a9ddfb0868b1efa9b9b96271ab62a27fa8afe8a76a9a6ba29" +
                "ae26ad7bea68b2c7acb22a27fa2b3e7256a299e77eb68f9b7be8a595e81a" +
                "97e8a7fad85ef949e2b5e77e4ad6ad7acfffffffffffffff";

        while (goal.length() < 512) {
            goal = goal + "00";
        }

        BigInteger q = rand(128);
        while (!q.isProbablePrime(10000)) {
            q = q.add(BigInteger.ONE);
        }
        BigInteger goalInt = new BigInteger(goal, 16);
        goalInt = goalInt.add(q.subtract(goalInt.mod(q)));
        if (!goalInt.mod(q).equals(BigInteger.ZERO)) {
            throw new IllegalStateException("badness");
        }

        BigInteger p = goalInt.divide(q);
        while (!p.isProbablePrime(10000)) {
            p = p.add(BigInteger.ONE);
        }
        System.out.println(p);
        System.out.println(q);

        BigInteger n = p.multiply(q);
        System.out.println(Base64.getEncoder().encodeToString(n.toByteArray()));

        BigInteger lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("10001", 16);
        BigInteger d = e.modInverse(lambda);

        RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(n, d));
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        PKCS10CertificationRequest csr = new PKCS10CertificationRequestBuilder(new X500Name("CN=foo.derp.fish"), bcPk)
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));
        System.out.println(Base64.getEncoder().encodeToString(csr.getEncoded()));
    }
}

