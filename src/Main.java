package no.polaric.cert; 

import no.polaric.core.*;
import no.polaric.core.httpd.*;
import io.javalin.Javalin;
import java.util.*;
import java.io.*;


/**
 * Server Main class. 
 * It implements the ServerConfig interface and starts the server. 
 */

public class Main extends ConfigBase implements ServerConfig {

    public  WebServer webserver;
    private  List<ServerConfig.SimpleCb> _shutdown = new ArrayList<ServerConfig.SimpleCb>();
    
    private Properties _defaultConf;
    public Logfile _caLog = new Logfile.Dummy(); 
    public KeyStoreLoader loader;
    public CertificateSigner signer;
    public String CA_ALIAS;
    public String CA_ISSUER;
    
    
    
    /** 
     * Important settings. 
     * The alloworigin setting is for CORS access
     * The other settings are config file locations. Config files are placed the 
     * conf subdirectory
     */
    public void settings(String[] args) {
        
        if (java.security.Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        
        /* Get settings from file - Java properties */
        if (args.length == 0) {
            System.out.println("ERROR: No arguments given. Expects config file path");
            System.exit(1);
        }
        try {
            System.out.println("Reading properties from : "+args[0]);
            FileInputStream fin = new FileInputStream(args[0]);
            _defaultConf = new Properties();
            _defaultConf.load(fin);
            fin.close(); 
            setConfig(_defaultConf);
            
            String KEYSTORE_PATH = getProperty("cacert.keystore", "keystore.p12");
            String KEYSTORE_PASSWORD = getProperty("cacert.keystore.pw", "1234");
            CA_ALIAS = getProperty("cacert.alias", "test_ca");
            CA_ISSUER = getProperty("cacert.issuer", "CN=test ca");
            boolean logon = getBoolProperty("cacert.log.on", false);
            String logfn = getProperty("cacert.log.file", "ca.log");
            if (logon)
                _caLog = new Logfile(this, "CA", logfn); 
                
            loader = new KeyStoreLoader(_caLog, KEYSTORE_PATH, KEYSTORE_PASSWORD);
            signer = new CertificateSigner(_caLog, loader, CA_ALIAS, CA_ISSUER);
            
        }
        catch (Exception e) {
            System.out.println("ERROR: "+e.getMessage());
            System.exit(1);
        }
        
    }
    
       
       
    public WebServer getWebserver()
        { return webserver; }
        
        
    /**
     * Add shutdown handler function. Differnet parts of the app may 
     * use this (with lambda functions) to do cleanup when server shuts down.
     */
    public void addShutdownHandler(SimpleCb cb){
        _shutdown.add(cb);
    }


    /**
     * Create and start the webserver. 
     */
    public void start() {
        webserver = new MyWebServer(this, 7077);
        webserver.start();
    }
    
    
    /** 
     * To be called when server terminates. Cleanup. 
     */
    public void stop() {
         for (ServerConfig.SimpleCb f: _shutdown)
            f.cb(); 
    }
    
    
    /**
     * The main method. Sets up and runs the server instance. 
     */
    public static void main(String[] args) 
    {
        Main setup = new Main(); 
        setup.settings(args);
        setup.start();        
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            setup.stop();
        }));
    }
}

