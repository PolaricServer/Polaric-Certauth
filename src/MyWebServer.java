 /* 
 * Copyright (C) 2025-2026 by LA7ECA, Øyvind Hanssen (ohanssen@acm.org)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
 
package no.polaric.cert;
import no.polaric.core.*;
import no.polaric.core.httpd.*;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import org.pac4j.core.config.Config;
import org.pac4j.javalin.*;
import java.util.*;

/**
 * Configuration of the HTTP server. 
 */
public class MyWebServer extends WebServer {
    
    public MyWebServer(ServerConfig conf, int port) {
        super(conf, port, "notify", "/", "./doc" );
    }
    
    
    @Override
    protected void setupRoutes() {
        /* Start Test REST API */
        CertApi a1 = new CertApi(_conf);
        a1.start();
    }
    
    
    
    public void start() {
        super.start(); 
        
        /* 
         * Handlers for login and logout. Here we just print message. 
         */
        onLogin( u-> {
            System.out.println("**** LOGIN:"+u+" ****");
        });
        
        onLogout( u-> {
            System.out.println("**** LOGOUT:"+u+" ****");
        });
        
        /* At shutdown. Send a message to other nodes */
        _conf.addShutdownHandler( ()-> {
            System.out.println("**** SHUTDOWN ****");
        });
    }
    
}


