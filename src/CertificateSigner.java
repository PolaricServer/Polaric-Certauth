package no.polaric.cert;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.X509Certificate;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Date;
import no.polaric.core.*;




public class CertificateSigner {

    // Instance variables wrapping your persistence context
    private final KeyStoreLoader keyStoreLoader;
    private final String caAlias;
    private final String caIssuerString;
    private Logfile log;
    
    /**
     * Constructs the Certificate Engine bound to a specific CA key manager context.
     * 
     * @param keyStoreLoader  An instance of your PKCS12 KeyStoreLoader
     * @param caAlias         The alias name of your Elliptic Curve CA key entry
     * @param caIssuerString  The Distinguished Name (DN) of your factory Root CA
     */
    public CertificateSigner(Logfile lg, KeyStoreLoader keyStoreLoader, String caAlias, String caIssuerString) {
        if (keyStoreLoader == null || caAlias == null || caIssuerString == null) {
            throw new IllegalArgumentException("Signing dependencies and configurations cannot be null.");
        }
        this.keyStoreLoader = keyStoreLoader;
        this.caAlias = caAlias;
        this.caIssuerString = caIssuerString;
        log = lg;
    }

    
    public PKCS10CertificationRequest parseCSR(String csrPem) throws Exception {
        // 1. Parse the incoming CSR
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new StringReader(csrPem))) {
            Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObject;
            } else {
                throw new IllegalArgumentException("Invalid or corrupted PKCS#10 CSR string payload.");
            }
        }
        return csr;
    }
    
    
    
    public X509Certificate parseCert(String pem) throws Exception {
        /* Parse the generated PEM back into an X509Certificate object to print attributes */
        X509Certificate cert;
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            X509CertificateHolder holder = (X509CertificateHolder) pemParser.readObject();
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        }
        return cert;
    }
    
    
    
    
    public String marshalCert(X509Certificate cert) throws Exception {
        X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
        return marshalCert(holder);
    }
    
    
    
    public String marshalCert(X509CertificateHolder certHolder) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certHolder);
        }
        return stringWriter.toString();
    }
    
        
    
    /**
     * Process an incoming PEM-encoded device CSR, extracts its SAN requirements, 
     * signs it with the loaded EC key, and returns the public certificate.
     * 
     * @param csr             The certicication request
     * @param validityDays    How many days the device certificate should remain valid
     * @return                The completed client certificate payload as a PEM string
     */
    public X509Certificate signCsr(PKCS10CertificationRequest csr, int validityDays) throws Exception {

        /* Setup the Timeline parameters */
        Date notBefore = new Date();
        long validityMillis = validityDays * 24L * 60L * 60L * 1000L;
        Date notAfter = new Date(notBefore.getTime() + validityMillis);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        /* Initialize the Certificate Structure */
        X500Name issuerName = new X500Name(this.caIssuerString);
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuerName, 
                serialNumber, 
                notBefore, 
                notAfter, 
                csr.getSubject(), 
                csr.getSubjectPublicKeyInfo()
        );

        /* Inject standard constrained client device profile extensions */
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        /* Extract and transparently forward requested SAN profiles using the optimized approach */
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions != null) {
            Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);
            if (sanExtension != null) {
                GeneralNames requestedSans = GeneralNames.getInstance(sanExtension.getParsedValue());
                certBuilder.addExtension(Extension.subjectAlternativeName, false, requestedSans);
            }
        }

        /* Leverage your instance's loader layer to fetch the Private Key on-demand */
        PrivateKey caPrivateKey = this.keyStoreLoader.getCaPrivateKey(this.caAlias);

        /* Cryptographically sign using EC signature profile */
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(caPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        log.info("CA", "Certificate request signed: "+csr.getSubject() ); 
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
}

