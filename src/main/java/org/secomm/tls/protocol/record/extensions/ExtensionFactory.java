package org.secomm.tls.protocol.record.extensions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ExtensionFactory {

    public interface ExtensionBuilder <T extends Extension> {
        public T build();
    }

    private static final Map<Short, ExtensionBuilder<?>> extensionsMap = Stream.of(new Object[][] {
            { Extensions.SERVER_NAME_INDICATION, new ServerNameIndicationExtension.Builder() }
    }).collect(Collectors.toMap(e -> (Short) e[0], e -> (ExtensionBuilder<?>) e[1]));

    private static List<Extension> currentExtensions = new ArrayList<>();

    public static <T extends Extension> T getExtension(short extensionType) throws InvalidExtensionTypeException {
        ExtensionBuilder builder = extensionsMap.get(extensionType);
        if (builder == null) {
            throw new InvalidExtensionTypeException("Unknown extension " + extensionType);
        }
        return (T) builder.build();
    }

    public static List<Extension> getCurrentExtensions() {
        return currentExtensions;
    }

    public static void setCurrentExtensions(final List<Extension> currentExtensions) {
        ExtensionFactory.currentExtensions = currentExtensions;
    }

    public static void addExtension(Extension extension) {
        currentExtensions.add(extension);
    }
}
