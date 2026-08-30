
package no.polaric.cert;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import no.polaric.core.*;




public class KeyStoreLoader {

    private final String keystorePath;
    private final String keystorePassword;
    private Logfile log;
    
    
    /**
     * Initializes the loader with a target PKCS12 KeyStore path and password.
     * Use file extensions like .p12 or .pfx.
     */
    public KeyStoreLoader(Logfile lg, String keystorePath, String keystorePassword) {
        if (keystorePath == null || keystorePassword == null) {
            throw new IllegalArgumentException("Keystore configuration parameters cannot be null.");
        }
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.log = lg;
    }

    
    public boolean caExists(String keyAlias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        File file = new File(this.keystorePath);
         
        /* Load existing file */
        if (file.exists())
            try (FileInputStream fis = new FileInputStream(file)) {
                keyStore.load(fis, this.keystorePassword.toCharArray());
            }
        else 
            return false;
      
        if (keyStore.containsAlias(keyAlias)) 
            return true;
        return false;
    }
    
    
    
    /**
     * Checks if the PKCS12 file and CA alias exist. If missing, it creates 
     * a brand new .p12 file and populates it with an EC self-signed Root CA.
     */
    public void initCa(String keyAlias, String caIssuerString) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        File file = new File(this.keystorePath);
        
        
        /* Load existing file or start fresh in memory */
        if (file.exists())
            try (FileInputStream fis = new FileInputStream(file)) {
                keyStore.load(fis, this.keystorePassword.toCharArray());
            }
        else 
            keyStore.load(null, this.keystorePassword.toCharArray());
    
        /* Generate EC Key Pair using the NIST P-256 (secp256r1) curve */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair caKeyPair = keyGen.generateKeyPair();

        // 4. Define validity timeline (10 years)
        Date notBefore = new Date();
        long tenYearsMillis = 10L * 365 * 24 * 60 * 60 * 1000;
        Date notAfter = new Date(notBefore.getTime() + tenYearsMillis);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        /* 5. Build self-signed CA Certificate */
        X500Name caName = new X500Name(caIssuerString);
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                caName, 
                serialNumber, 
                notBefore, 
                notAfter, 
                caName, 
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );

        /* Define Root CA constraints */
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        /* Cryptographically sign using SHA256withECDSA */
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(caKeyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        /*
         * Put the new entry into the KeyStore object 
         * NOTE: For PKCS12, the key password MUST match the keystore password
         */
        Certificate[] chain = new Certificate[]{ caCert };
        keyStore.setKeyEntry(keyAlias, caKeyPair.getPrivate(), this.keystorePassword.toCharArray(), chain);

        /* Persist the file structure back to disk */
        if (file.getParentFile() != null) {
            file.getParentFile().mkdirs();
        }
        try (FileOutputStream fos = new FileOutputStream(file)) {
            keyStore.store(fos, this.keystorePassword.toCharArray());
        }
        log.info("CA", "Generated and saved new PKCS12 Root CA to: " + file.getAbsolutePath());
    }

    
    
    /**
     * Return the CA private key. 
     */
    public final PrivateKey getCaPrivateKey(String keyAlias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(this.keystorePath)) {
            keyStore.load(fis, this.keystorePassword.toCharArray());
        }

        // Retrieves the private key using the uniform keystore password
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, this.keystorePassword.toCharArray());
        if (privateKey == null) {
            throw new IllegalArgumentException("No private key found under alias: " + keyAlias);
        }

        return privateKey;
    }

    
    
    public X509Certificate getCaCertificate(String keyAlias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(this.keystorePath)) {
            keyStore.load(fis, this.keystorePassword.toCharArray());
        }
        
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
        if (cert == null) 
            throw new IllegalArgumentException("No certificate found under alias: " + keyAlias);
        return cert;
    }
    
    
    
    /**
     * Retrieves the Root CA Certificate from the configured KeyStore and exports it to PEM format.
     */
    public String exportCaCertificate(String keyAlias) throws Exception {
        Certificate caCert = getCaCertificate(keyAlias);
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(caCert);
        }

        return stringWriter.toString();
    }
    
}
