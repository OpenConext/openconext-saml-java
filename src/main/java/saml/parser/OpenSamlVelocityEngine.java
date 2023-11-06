package saml.parser;


import net.shibboleth.utilities.java.support.velocity.VelocityEngine;
import org.apache.velocity.VelocityContext;
import org.slf4j.helpers.NOPLogger;

import java.io.Writer;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OpenSamlVelocityEngine {

    private final org.apache.velocity.app.VelocityEngine velocityEngine;

    public OpenSamlVelocityEngine() {
        this.velocityEngine = VelocityEngine.newVelocityEngine();
        velocityEngine.setProperty("runtime.log.instance", NOPLogger.NOP_LOGGER);
        velocityEngine.setProperty("velocimacro.library.autoreload", false);
        velocityEngine.setProperty("resource.loader.file.cache", true);
        velocityEngine.setProperty("resource.loader.file.modificationCheckInterval", -1);
        velocityEngine.init();
    }

    public void process(String templateId,
                        Map<String, Object> model,
                        Writer out) {
        VelocityContext context = new VelocityContext(model);
        velocityEngine.mergeTemplate(templateId, UTF_8.name(), context, out);
    }

}
