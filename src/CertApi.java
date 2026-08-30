 
package no.polaric.cert;
import no.polaric.core.*;
import no.polaric.core.httpd.*;
import no.polaric.core.auth.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.security.cert.X509Certificate;




/**
 * Simple example of a RESTful API. 
 * See also the Javalin documentation. 
 */
 
public class CertApi extends ServerBase {

    private String CA_ALIAS;
    private Main myconf; 
    private int maxdays; 
    
    
    public CertApi(ServerConfig conf) {
        super(conf);
        CA_ALIAS = conf.getProperty("cacert.alias", "test_ca");
        maxdays = conf.getIntProperty("cacert.maxdays", 768);
        myconf = (Main) conf;
    }
    
    
    /** 
     * Return an error status message to client. 
     * FIXME: Move to superclass. 
     */
    public void ERROR(Context ctx, int status, String msg)
      { myconf.log().warn("certapi", msg);
        ctx.status(status); ctx.result(msg); }
      
      

    public void start() {

        protect("/cacert/sign");
        
        
        
        /*
         * Unprotected GET service. Return PEM representation of CA certificate
         */
        a.get("/cacert", ctx -> {
            try {
                String caCertPem = myconf.loader.exportCaCertificate(CA_ALIAS);
                ctx.result(caCertPem);
            } catch (java.io.FileNotFoundException e) {
                ERROR(ctx, 500, "KeyStore file not found.");
            } catch (Exception e) {
                ERROR(ctx, 500, "Failed to fetch CA certificate: " + e.getMessage());
            }
        });
    
    
        /*
         * Protected POST service. Sign a certificate (CSR)
         */
        a.post("/cacert/sign", ctx -> {
            try {
                int days = maxdays;
                String dayss = ctx.queryParam("days"); 
                if (dayss != null)
                    days = Integer.parseInt(dayss);
                if (days > maxdays)
                    days = maxdays;
                    
                PKCS10CertificationRequest csr = myconf.signer.parseCSR(ctx.body());
                X509Certificate cert = myconf.signer.signCsr(csr, days);
                ctx.contentType("application/x-pem-file");
                ctx.result(myconf.signer.marshalCert(cert));
            }
            catch (NumberFormatException e) {
                ERROR(ctx, 400, "Malformed parameter value (days)");
            }
            catch (IllegalArgumentException e) {
                ERROR(ctx, 400, "Failed to sign CSR: "+e.getMessage());
            }
            catch (Exception e) {
                ERROR(ctx, 500, "Failed to sign CSR: "+e.getMessage());
            }
        });
        
    }
    

}
