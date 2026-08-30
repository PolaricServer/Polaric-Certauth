    
package no.polaric.cert;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.FileInputStream;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Scanner;




public class CaShell {


    public static void main(String[] args) {
       
        Main conf = new Main();
        conf.settings(args);
        Scanner scanner = new Scanner(System.in);

        System.out.println("==========================================");
        System.out.println("   Polaric CA Management System CLI");
        System.out.println("==========================================");
        System.out.println("Issuer: "+conf.CA_ISSUER);
        System.out.println();
        printHelp();

        while (true) {
            System.out.print("\npolaric-ca> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit") || input.equalsIgnoreCase("q")) {
                System.out.println("Exiting shell. Goodbye.");
                break;
            }

            switch (input.toLowerCase()) {
                case "help":
                    printHelp();
                    break;

                case "ca-create":
                    try {
                        if (conf.loader.caExists(conf.CA_ALIAS)) {
                            System.out.println("WARNING: CA already exists. Replace it (y/n)?");
                            char c = scanner.next().charAt(0);
                            if (c != 'y' && c != 'Y')
                                break;
                        }
                            
                        System.out.println("Initializing Root CA: "+conf.CA_ALIAS+": "+conf.CA_ISSUER);
                        conf.loader.initCa(conf.CA_ALIAS, conf.CA_ISSUER);
                        System.out.println("SUCCESS: CA identity is ready and verified.");
                    } catch (Exception e) {
                        System.err.println("ERROR: Could not create CA: " + e.getMessage());
                    }
                    break;

                    
                case "ca-pem":
                    try {
                        String caCertPem = conf.loader.exportCaCertificate(conf.CA_ALIAS);
                        System.out.println(caCertPem);
                    } catch (java.io.FileNotFoundException e) {
                        System.err.println("ERROR: KeyStore file not found. Run 'ca-create' first.");
                    } catch (Exception e) {
                        System.err.println("ERROR: Failed to fetch CA certificate: " + e.getMessage());
                    }
                    break;

                    
                case "ca-details":
                    try {
                        X509Certificate cert = (X509Certificate) conf.loader.getCaCertificate(conf.CA_ALIAS);
                        if (cert == null) 
                            throw new IllegalArgumentException("No certificate found under alias: " + conf.CA_ALIAS);

                        System.out.println("\n=== ROOT CA CERTIFICATE DETAILS ===");
                        printCertificateDetails(cert);

                    } catch (java.io.FileNotFoundException e) {
                        System.err.println("ERROR: KeyStore file not found. Run 'ca-create' first.");
                    } catch (Exception e) {
                        System.err.println("ERROR: Failed to analyze certificate structure: " + e.getMessage());
                    }
                    break;

                    
                case "sign":
                    try {
                        String csrPem = readMultiLinePem(scanner);
                        if (csrPem.isEmpty()) {
                            System.out.println("Aborted. No input detected.");
                            break;
                        }
                        
                        PKCS10CertificationRequest csr = conf.signer.parseCSR(csrPem);
                        System.out.println("Subject: "+csr.getSubject());
                        System.out.println();
                        
                        System.out.print("Enter validity period in days (default 365): ");
                        String dd = scanner.nextLine().trim();
                        int days = 365; 
                        if (!"".equals(dd))
                            days = Integer.parseInt(scanner.nextLine().trim());

                        X509Certificate cert = conf.signer.signCsr(csr, days);

                        System.out.println("\n=== NEWLY SIGNED CERTIFICATE DETAILS ===");
                        printCertificateDetails(cert);

                        System.out.println(conf.signer.marshalCert(cert));
                    } catch (NumberFormatException e) {
                        System.err.println("ERROR: Invalid number format for validity days.");
                    } catch (Exception e) {
                        System.err.println("ERROR: Signing failed: " + e.getMessage());
                    }
                    break;

                default:
                    System.out.println("Unknown command: '" + input + "'. Type 'help' for options.");
            }
        }
        scanner.close();
    }

    

    
    
    /**
     * Shared modular method formatting and printing attributes of any X509 Certificate instance.
     */
    private static void printCertificateDetails(X509Certificate cert) throws Exception {
        System.out.println("Subject DN:      " + cert.getSubjectX500Principal());
        System.out.println("Issuer DN:       " + cert.getIssuerX500Principal());
        System.out.println("Serial Number:   " + cert.getSerialNumber().toString(16).toUpperCase());
        System.out.println("Version:         V" + cert.getVersion());
        System.out.println("Valid From:      " + cert.getNotBefore());
        System.out.println("Valid Until:     " + cert.getNotAfter());
        System.out.println("Sig Algorithm:   " + cert.getSigAlgName());
        
        if (cert.getPublicKey() instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) cert.getPublicKey();
            System.out.println("Public Key Type: Elliptic Curve (EC)");
            System.out.println("Key Size:        " + ecKey.getParams().getCurve().getField().getFieldSize() + " bits");
        } else 
            System.out.println("Public Key Type: " + cert.getPublicKey().getAlgorithm());

        System.out.println("\n[X509v3 Extensions]");
        
        /* Basic Constraints */
        int pathLen = cert.getBasicConstraints();
        System.out.println("  Basic Constraints: Is CA = " + (pathLen >= 0));
        
        /* Key Usage */
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            System.out.print("  Key Usages:        ");
            if (keyUsage.length > 0 && keyUsage[0]) System.out.print("[Digital Signature] ");
            if (keyUsage.length > 5 && keyUsage[5]) System.out.print("[Key Cert Sign] ");
            if (keyUsage.length > 6 && keyUsage[6]) System.out.print("[CRL Sign] ");
            System.out.println();
        }

        /* Subject Alternative Names (SAN) Extraction */
        if (cert.getSubjectAlternativeNames() != null) {
            System.out.println("  Subject Alt Names (SAN):");
            for (java.util.List<?> sanItem : cert.getSubjectAlternativeNames()) 
                System.out.println("    - " + sanItem.get(1));
        }
    }
    

    private static void printHelp() {
        System.out.println("Available Commands:");
        System.out.println("  ca-create       - Generates a new P-256 EC Root CA certificate.");
        System.out.println("  ca-pem          - Displays the public CA certificate string.");
        System.out.println("  ca-details      - Inspects and lists human-readable properties of the CA.");
        System.out.println("  sign            - Read a CSR from the terminal and sign it");
        System.out.println("  help            - Shows this menu options guide.");
        System.out.println("  exit or q       - Closes the active session environment.");
    }

    
    private static String readMultiLinePem(Scanner scanner) {
        System.out.println("Paste your PEM string payload below (Type '.' or 'END' on a empty line when finished):");
        StringBuilder sb = new StringBuilder();
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            if (line.trim().equals(".") || line.trim().equalsIgnoreCase("END")) {
                break;
            }
            sb.append(line).append("\n");
        }
        return sb.toString().trim();
    }
}
