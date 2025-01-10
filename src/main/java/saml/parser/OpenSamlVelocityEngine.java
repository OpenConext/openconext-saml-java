package saml.parser;


import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.slf4j.helpers.NOPLogger;

import java.io.Writer;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OpenSamlVelocityEngine {

    private static final String templateId = "/templates/saml2-post-binding.vm";
    private final VelocityEngine velocityEngine;

    public OpenSamlVelocityEngine() {
        this.velocityEngine = new VelocityEngine();
        velocityEngine.setProperty("resource.loader.string.class", "org.apache.velocity.runtime.resource.loader.StringResourceLoader");
        velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.setProperty("resource.loaders", "classpath, string");
        velocityEngine.setProperty("runtime.log.instance", NOPLogger.NOP_LOGGER);
        velocityEngine.setProperty("velocimacro.library.autoreload", false);
        velocityEngine.setProperty("resource.loader.file.cache", true);
        velocityEngine.setProperty("resource.loader.file.modificationCheckInterval", -1);
        this.velocityEngine.init();
    }

    public void process(Map<String, Object> model, Writer out) {
        velocityEngine.mergeTemplate(templateId, UTF_8.name(), new VelocityContext(model), out);
    }

}
